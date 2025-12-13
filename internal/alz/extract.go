package alz

import (
	"compress/flate"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/blurfx/unegg/internal/archive"
	"github.com/blurfx/unegg/internal/crypto"
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

	// ErrWrongPassword indicates the provided password is incorrect.
	ErrWrongPassword = archive.ErrWrongPassword
)

// ExtractAll extracts all files in the archive to the destination folder.
func (a *Archive) ExtractAll(opts ExtractOptions) error {
	opts = opts.WithDefaults()

	if err := os.MkdirAll(opts.Dest, 0o755); err != nil {
		return err
	}

	readerAt, cleanup, err := a.getReader()
	if err != nil {
		return err
	}
	defer cleanup()

	type task struct {
		file *File
	}
	tasks := make(chan task)
	errCh := make(chan error, opts.Concurrency)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for t := range tasks {
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "extracting: %s\n", t.file.Name)
			}
			if err := extractFile(readerAt, opts.Dest, t.file, opts.Password, a.multi); err != nil {
				errCh <- err
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
		case tasks <- task{file: &a.Files[i]}:
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

func extractFile(arc io.ReaderAt, dest string, f *File, password string, allowBadCRC bool) error {
	name := f.Name
	if name == "" {
		name = fmt.Sprintf("%08d", f.Index)
	}

	fullPath, err := archive.SecureJoin(dest, name)
	if err != nil {
		return err
	}

	if f.Attributes&FileAttributeDirectory != 0 {
		if err := os.MkdirAll(fullPath, 0o755); err != nil {
			return err
		}
		if !f.ModTime.IsZero() {
			_ = os.Chtimes(fullPath, f.ModTime, f.ModTime)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return err
	}

	out, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer out.Close()

	dec, err := buildDecryptor(f, password)
	if err != nil {
		return err
	}

	if err := decodeFile(arc, out, f, dec, allowBadCRC); err != nil {
		return err
	}

	if err := dec.Finish(); err != nil {
		return err
	}

	if !f.ModTime.IsZero() {
		_ = os.Chtimes(fullPath, f.ModTime, f.ModTime)
	}
	return nil
}

func decodeFile(arc io.ReaderAt, out *os.File, f *File, dec crypto.Decryptor, allowBadCRC bool) error {
	if f.PackSize > uint64(^uint64(0)>>1) {
		return fmt.Errorf("alz: pack size too large")
	}

	src := io.NewSectionReader(arc, f.Offset, int64(f.PackSize))

	var r io.Reader = src
	if dec != nil {
		r = &crypto.DecryptReader{R: src, Dec: dec}
	}
	limited := io.LimitReader(r, int64(f.PackSize))

	crc := crc32.NewIEEE()
	counter := &crypto.WriteCounter{W: out}
	dst := io.MultiWriter(counter, crc)

	var err error
	switch f.Method {
	case 0: // store
		_, err = io.CopyN(dst, limited, int64(f.Size))
	case 2: // deflate
		fr := flate.NewReader(limited)
		defer fr.Close()
		_, err = io.CopyN(dst, fr, int64(f.Size))
	default:
		err = ErrUnsupportedMethod
	}
	if err != nil {
		return err
	}

	if counter.N != int64(f.Size) {
		return fmt.Errorf("alz: short decode (want %d, got %d)", f.Size, counter.N)
	}
	if crc.Sum32() != f.CRC {
		if allowBadCRC {
			return nil
		}
		return fmt.Errorf("alz: crc mismatch")
	}
	return nil
}

func buildDecryptor(f *File, password string) (crypto.Decryptor, error) {
	if !f.Encrypted {
		return crypto.NopDecryptor{}, nil
	}
	if password == "" {
		return nil, ErrWrongPassword
	}
	return crypto.NewZipDecryptor(password, f.Verify, f.CRC)
}

func (a *Archive) getReader() (io.ReaderAt, func(), error) {
	if a.reader != nil {
		cleanup := a.cleanup
		if cleanup == nil {
			cleanup = func() {}
		}
		return a.reader, cleanup, nil
	}
	f, err := os.Open(a.path)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}
