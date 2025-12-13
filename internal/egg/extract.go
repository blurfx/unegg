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
	"sync"
	"time"

	"github.com/blurfx/unegg/internal/archive"
	"github.com/blurfx/unegg/internal/crypto"
	"github.com/ulikunitz/xz/lzma"
)

// ExtractOptions is an alias to archive.ExtractOptions.
// Using a type alias maintains backward compatibility while allowing
// the type to be shared across packages without circular dependencies.
type ExtractOptions = archive.ExtractOptions

// Extraction errors are aliased from archive package.
// These aliases maintain backward compatibility while centralizing error
// definitions in a shared package, avoiding duplication and circular dependencies.
var (
	// ErrUnsupportedMethod indicates an unsupported compression method.
	ErrUnsupportedMethod = archive.ErrUnsupportedMethod

	// ErrUnsupportedCrypto indicates an unsupported encryption method.
	ErrUnsupportedCrypto = archive.ErrUnsupportedEncryption

	// ErrWrongPassword indicates the provided password is incorrect.
	ErrWrongPassword = archive.ErrWrongPassword
)

type solidOutput struct {
	path      string
	file      *os.File
	remaining int64
	modTime   time.Time
}

// ExtractAll extracts all files in the archive to the destination folder.
func (a *Archive) ExtractAll(opts ExtractOptions) error {
	opts = opts.WithDefaults()

	if a.IsSolid {
		return a.extractSolid(opts)
	}

	if err := os.MkdirAll(opts.Dest, 0o755); err != nil {
		return err
	}

	readerAt, cleanup, err := a.getReader()
	if err != nil {
		return err
	}
	defer cleanup()

	type task struct {
		file File
	}
	tasks := make(chan task)
	var wg sync.WaitGroup
	errCh := make(chan error, opts.Concurrency)

	worker := func() {
		defer wg.Done()
		for t := range tasks {
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "extracting: %s\n", t.file.Path)
			}
			if err := extractFile(readerAt, opts.Dest, &t.file, opts.Password); err != nil {
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

func (a *Archive) extractSolid(opts ExtractOptions) error {
	if err := os.MkdirAll(opts.Dest, 0o755); err != nil {
		return err
	}

	readerAt, cleanup, err := a.getReader()
	if err != nil {
		return err
	}
	defer cleanup()

	var outputs []solidOutput
	for i := range a.Files {
		file := &a.Files[i]
		if file.Path == "" {
			file.Path = fmt.Sprintf("%08d", file.Index)
		}

		fullPath, err := archive.SecureJoin(opts.Dest, file.Path)
		if err != nil {
			return err
		}

		if file.Attributes&FileAttributeDirectory != 0 {
			if err := os.MkdirAll(fullPath, 0o755); err != nil {
				return err
			}
			if !file.ModTime.IsZero() {
				_ = os.Chtimes(fullPath, file.ModTime, file.ModTime)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return err
		}
		out, err := os.Create(fullPath)
		if err != nil {
			return err
		}
		outputs = append(outputs, solidOutput{
			path:      fullPath,
			file:      out,
			remaining: int64(file.Size),
			modTime:   file.ModTime,
		})
	}

	sink := &solidWriter{outputs: outputs}
	for _, block := range a.SolidBlocks {
		if err := decodeSolidBlock(readerAt, &block, sink); err != nil {
			return err
		}
	}
	return sink.close()
}

func extractFile(arc io.ReaderAt, dest string, f *File, password string) error {
	if f.Path == "" {
		f.Path = fmt.Sprintf("%08d", f.Index)
	}

	fullPath, err := archive.SecureJoin(dest, f.Path)
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
		if err := decodeBlock(arc, out, &block, dec); err != nil {
			return err
		}
	}

	if err := dec.Finish(); err != nil {
		return err
	}

	if !f.ModTime.IsZero() {
		_ = os.Chtimes(fullPath, f.ModTime, f.ModTime)
	}
	return nil
}

func decodeSolidBlock(arc io.ReaderAt, block *Block, dst io.Writer) error {
	src := io.NewSectionReader(arc, block.Offset, int64(block.PackSize))
	limited := io.LimitReader(src, int64(block.PackSize))

	crc := crc32.NewIEEE()
	counter := &crypto.WriteCounter{W: io.Discard}
	target := io.MultiWriter(dst, crc, counter)

	var err error
	switch block.Method {
	case 0: // store
		_, err = io.CopyN(target, limited, int64(block.UnpackSize))
	case 1: // deflate
		fr := flate.NewReader(limited)
		defer fr.Close()
		_, err = io.CopyN(target, fr, int64(block.UnpackSize))
	case 2: // bzip2
		br := bzip2.NewReader(limited)
		_, err = io.CopyN(target, br, int64(block.UnpackSize))
	case 3: // AZO (not implemented)
		err = ErrUnsupportedMethod
	case 4: // LZMA
		err = decodeLZMA(limited, block, target)
	default:
		err = ErrUnsupportedMethod
	}
	if err != nil {
		return err
	}

	if counter.N != int64(block.UnpackSize) {
		return fmt.Errorf("egg: short decode (want %d, got %d)", block.UnpackSize, counter.N)
	}
	if crc.Sum32() != block.CRC {
		return fmt.Errorf("egg: crc mismatch")
	}
	return nil
}

func decodeBlock(arc io.ReaderAt, out *os.File, block *Block, dec crypto.Decryptor) error {
	src := io.NewSectionReader(arc, block.Offset, int64(block.PackSize))

	var r io.Reader = src
	if dec != nil {
		r = &crypto.DecryptReader{R: src, Dec: dec}
	}
	limited := io.LimitReader(r, int64(block.PackSize))

	crc := crc32.NewIEEE()
	counter := &crypto.WriteCounter{W: out}
	dst := io.MultiWriter(counter, crc)

	var err error
	switch block.Method {
	case 0: // store
		_, err = io.CopyN(dst, limited, int64(block.UnpackSize))
	case 1: // deflate
		fr := flate.NewReader(limited)
		defer fr.Close()
		_, err = io.CopyN(dst, fr, int64(block.UnpackSize))
	case 2: // bzip2
		br := bzip2.NewReader(limited)
		_, err = io.CopyN(dst, br, int64(block.UnpackSize))
	case 3: // AZO (not implemented)
		err = ErrUnsupportedMethod
	case 4: // LZMA
		err = decodeLZMA(limited, block, dst)
	default:
		err = ErrUnsupportedMethod
	}
	if err != nil {
		return err
	}

	if counter.N != int64(block.UnpackSize) {
		return fmt.Errorf("egg: short decode (want %d, got %d)", block.UnpackSize, counter.N)
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

func buildDecryptor(enc *EncryptionInfo, password string) (crypto.Decryptor, error) {
	if enc == nil {
		return crypto.NopDecryptor{}, nil
	}
	if password == "" {
		return nil, ErrWrongPassword
	}

	switch enc.Method {
	case 0: // ZipCrypto
		return crypto.NewZipDecryptor(password, enc.ZipVerify, enc.ZipCRC)
	case 1, 2: // AES-128, AES-256
		return crypto.NewAESDecryptor(enc.Method, password, enc.Salt, enc.Mac)
	case 5, 6: // LEA (not implemented)
		return nil, ErrUnsupportedCrypto
	default:
		return nil, ErrUnsupportedCrypto
	}
}

type solidWriter struct {
	outputs []solidOutput
	index   int
}

func (s *solidWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if s.index >= len(s.outputs) {
			return written, fmt.Errorf("egg: solid stream has extra data")
		}
		cur := &s.outputs[s.index]
		if cur.remaining == 0 {
			if cur.file != nil {
				if err := cur.file.Close(); err != nil {
					return written, err
				}
				if !cur.modTime.IsZero() {
					_ = os.Chtimes(cur.path, cur.modTime, cur.modTime)
				}
				cur.file = nil
			}
			s.index++
			continue
		}
		if int64(len(p)) <= cur.remaining {
			n, err := cur.file.Write(p)
			cur.remaining -= int64(n)
			written += n
			return written, err
		}
		// Partial write to finish current file.
		chunk := cur.remaining
		n, err := cur.file.Write(p[:chunk])
		cur.remaining -= int64(n)
		written += n
		if err != nil {
			return written, err
		}
		p = p[chunk:]
	}
	return written, nil
}

func (s *solidWriter) close() error {
	for i := range s.outputs {
		cur := &s.outputs[i]
		if cur.remaining != 0 {
			return fmt.Errorf("egg: solid stream ended early")
		}
		if cur.file != nil {
			if err := cur.file.Close(); err != nil {
				return err
			}
			if !cur.modTime.IsZero() {
				_ = os.Chtimes(cur.path, cur.modTime, cur.modTime)
			}
		}
	}
	return nil
}

func (a *Archive) getReader() (io.ReaderAt, func(), error) {
	if a.reader != nil {
		return a.reader, func() {}, nil
	}
	f, err := os.Open(a.path)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}
