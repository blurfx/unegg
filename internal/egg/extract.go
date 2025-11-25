package egg

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ulikunitz/xz/lzma"
)

type ExtractOptions struct {
	Dest        string
	Password    string
	Concurrency int
}

// ExtractAll extracts every file in the archive to the destination folder.
func (a *Archive) ExtractAll(opts ExtractOptions) error {
	if opts.Dest == "" {
		opts.Dest = "."
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = runtime.NumCPU()
	}
	if err := os.MkdirAll(opts.Dest, 0o755); err != nil {
		return err
	}

	f, err := os.Open(a.path)
	if err != nil {
		return err
	}
	defer f.Close()

	type task struct {
		file File
	}
	tasks := make(chan task)
	var wg sync.WaitGroup
	errCh := make(chan error, opts.Concurrency)

	worker := func() {
		defer wg.Done()
		for t := range tasks {
			if err := extractFile(f, opts.Dest, &t.file, opts.Password); err != nil {
				errCh <- fmt.Errorf("%s: %w", t.file.Path, err)
				return
			}
		}
	}

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	for i := range a.Files {
		select {
		case err := <-errCh:
			close(tasks)
			wg.Wait()
			return err
		case tasks <- task{file: a.Files[i]}:
		}
	}
	close(tasks)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}
	return nil
}

func extractFile(archive *os.File, dest string, f *File, password string) error {
	if f.Path == "" {
		f.Path = fmt.Sprintf("%08d", f.Index)
	}
	fullPath, err := secureJoin(dest, f.Path)
	if err != nil {
		return err
	}

	if f.Attributes&FileAttributeDirectory != 0 {
		return os.MkdirAll(fullPath, 0o755)
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer out.Close()

	dec, err := buildDecryptor(f.Encryption, password)
	if err != nil {
		return err
	}

	for _, block := range f.Blocks {
		if err := decodeBlock(archive, out, &block, dec); err != nil {
			return err
		}
	}
	if err := dec.Finish(); err != nil {
		return err
	}

	// adjust mod time if available
	if !f.ModTime.IsZero() {
		_ = os.Chtimes(fullPath, f.ModTime, f.ModTime)
	}
	return nil
}

func decodeBlock(archive *os.File, out *os.File, block *Block, dec decryptor) error {
	src := io.NewSectionReader(archive, block.Offset, int64(block.PackSize))
	var r io.Reader = src
	if dec != nil {
		r = &decryptReader{r: src, dec: dec}
	}
	limited := io.LimitReader(r, int64(block.PackSize))

	crc := crc32.NewIEEE()
	counter := &writeCounter{w: out}
	dst := io.MultiWriter(counter, crc)

	var err error
	switch block.Method {
	case 0: // store
		_, err = io.CopyN(dst, limited, int64(block.UnpackSize))
	case 1: // deflate (raw)
		var fr io.ReadCloser
		fr = flate.NewReader(limited)
		defer fr.Close()
		_, err = io.CopyN(dst, fr, int64(block.UnpackSize))
	case 2: // bzip2
		br := bzip2.NewReader(limited)
		_, err = io.CopyN(dst, br, int64(block.UnpackSize))
	case 3: // AZO
		err = ErrUnsupportedMethod
	case 4: // LZMA
		err = decodeLZMA(limited, block, dst)
	default:
		err = ErrUnsupportedMethod
	}
	if err != nil {
		return err
	}

	if counter.n != int64(block.UnpackSize) {
		return fmt.Errorf("egg: short decode (want %d, got %d)", block.UnpackSize, counter.n)
	}
	if crc.Sum32() != block.CRC {
		return fmt.Errorf("egg: crc mismatch")
	}
	return nil
}

func decodeLZMA(r io.Reader, block *Block, dst io.Writer) error {
	if block.PackSize < 9 {
		return fmt.Errorf("egg: lzma block too small")
	}
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	props := header[4:]

	lzmaHeader := make([]byte, 13)
	copy(lzmaHeader[:5], props)
	binary.LittleEndian.PutUint64(lzmaHeader[5:], uint64(block.UnpackSize))

	stream := io.MultiReader(bytes.NewReader(lzmaHeader), r)
	zr, err := lzma.NewReader(stream)
	if err != nil {
		return err
	}

	_, err = io.CopyN(dst, zr, int64(block.UnpackSize))
	return err
}

func buildDecryptor(enc *EncryptionInfo, password string) (decryptor, error) {
	if enc == nil {
		return nopDecryptor{}, nil
	}
	if password == "" {
		return nil, ErrWrongPassword
	}

	switch enc.Method {
	case 0:
		return newZipDecryptor(password, enc.ZipVerify, enc.ZipCRC)
	case 1, 2:
		return newAESDecryptor(enc.Method, password, enc.Salt, enc.Mac)
	case 5, 6:
		return nil, ErrUnsupportedCrypto
	default:
		return nil, ErrUnsupportedCrypto
	}
}

type decryptReader struct {
	r   io.Reader
	dec decryptor
}

func (d *decryptReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if n > 0 {
		if derr := d.dec.Decrypt(p[:n]); derr != nil {
			return n, derr
		}
	}
	return n, err
}

type writeCounter struct {
	w io.Writer
	n int64
}

func (c *writeCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// secureJoin ensures the resulting path stays within the base directory.
func secureJoin(base, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("egg: illegal path %q", rel)
	}
	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("egg: illegal path %q", rel)
	}

	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	joined := filepath.Join(baseAbs, rel)
	prefix := baseAbs
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if joined != baseAbs && !strings.HasPrefix(joined, prefix) {
		return "", fmt.Errorf("egg: illegal path %q", rel)
	}
	return joined, nil
}
