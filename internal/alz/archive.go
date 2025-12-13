package alz

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blurfx/unegg/internal/archive"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/transform"
)

// Internal format signatures.
const (
	signatureFile    = 0x015A4C42 // "BLZ\x01"
	signatureComment = 0x015A4C45 // "ELZ\x01"

	flagEncrypted = 0x01
	flagSizeMask  = 0xF0
	sizeLenShift  = 4
)

// SignatureAlzHeader is the ALZ archive magic number (exported for format detection).
const SignatureAlzHeader = 0x015A4C41 // "ALZ\x01"

// FileAttributeDirectory indicates a directory entry in file attributes.
const FileAttributeDirectory = 0x10

// Package errors.
var (
	// ErrBadSignature indicates the file is not a valid ALZ archive.
	ErrBadSignature = archive.ErrBadSignature
)

type Archive struct {
	Version uint16
	ID      uint16
	Comment string
	Files   []File

	path    string
	size    int64
	reader  io.ReaderAt
	cleanup func()
	multi   bool
}

type File struct {
	Index      int
	Name       string
	Attributes uint32
	ModTime    time.Time

	Method    uint16
	PackSize  uint64
	Size      uint64
	CRC       uint32
	Offset    int64
	Encrypted bool
	Verify    []byte
	Comment   string
}

func Parse(path string) (*Archive, error) {
	readerAt, size, cleanup, multi, err := buildReader(path)
	if err != nil {
		return nil, err
	}
	if size < 16 {
		return nil, fmt.Errorf("alz: file too small")
	}

	endInfos, err := readEndInfos(readerAt, size)
	if err != nil {
		return nil, err
	}

	r := &reader{r: readerAt, size: size}

	sig, err := r.u32()
	if err != nil {
		return nil, err
	}
	if sig != SignatureAlzHeader {
		return nil, ErrBadSignature
	}

	version, err := r.u16()
	if err != nil {
		return nil, err
	}
	id, err := r.u16()
	if err != nil {
		return nil, err
	}

	arc := &Archive{
		Version: version,
		ID:      id,
		path:    path,
		size:    size,
	}
	if cleanup != nil {
		arc.reader = readerAt
		arc.cleanup = cleanup
	}
	arc.multi = multi

	var sigNext uint32
	for {
		sigNext, err = r.u32()
		if err != nil {
			// In split archives, we may hit EOF after the last file's pack data
			// because the data spans to the end of the concatenated segments.
			if (err == io.EOF || err == io.ErrUnexpectedEOF) && len(arc.Files) > 0 {
				break
			}
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if sigNext != signatureFile {
			break
		}
		file, err := parseFile(r, len(arc.Files))
		if err != nil {
			return nil, err
		}
		arc.Files = append(arc.Files, *file)
		if err := r.skip(int64(file.PackSize)); err != nil {
			return nil, err
		}
	}

	if sigNext == signatureComment {
		commentSize := endInfos[1]
		if commentSize <= 4 {
			return nil, fmt.Errorf("alz: invalid comment size %d", commentSize)
		}
		if err := parseComments(r, arc, int64(commentSize-4)); err != nil {
			return nil, err
		}
	}

	return arc, nil
}

func parseFile(r *reader, index int) (*File, error) {
	filenameLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	attrByte, err := r.u8()
	if err != nil {
		return nil, err
	}
	datetime, err := r.u32()
	if err != nil {
		return nil, err
	}
	flags, err := r.u16()
	if err != nil {
		return nil, err
	}

	sizeLen := int((flags & flagSizeMask) >> sizeLenShift)

	file := &File{
		Index:      index,
		Attributes: mapAttributes(attrByte),
		ModTime:    dosTimeToTime(datetime),
	}

	if sizeLen > 0 {
		if sizeLen != 1 && sizeLen != 2 && sizeLen != 4 && sizeLen != 8 {
			return nil, fmt.Errorf("alz: unsupported size length %d", sizeLen)
		}
		method, err := r.u16()
		if err != nil {
			return nil, err
		}
		crc, err := r.u32()
		if err != nil {
			return nil, err
		}
		pack, err := readSizedInt(r, sizeLen)
		if err != nil {
			return nil, err
		}
		unpack, err := readSizedInt(r, sizeLen)
		if err != nil {
			return nil, err
		}
		file.Method = method
		file.CRC = crc
		file.PackSize = pack
		file.Size = unpack
	}

	if filenameLen > 0 {
		raw, err := r.bytes(int(filenameLen))
		if err != nil {
			return nil, err
		}
		name, err := decodeName(raw)
		if err != nil {
			return nil, err
		}
		file.Name = cleanPath(name)
	}

	if flags&flagEncrypted != 0 {
		verify, err := r.bytes(12)
		if err != nil {
			return nil, err
		}
		file.Encrypted = true
		file.Verify = verify
	}

	file.Offset = r.pos()
	return file, nil
}

func parseComments(r *reader, arc *Archive, remaining int64) error {
	for remaining > 0 {
		if remaining < 6 {
			return fmt.Errorf("alz: truncated comment section")
		}
		idx, err := r.u32()
		if err != nil {
			return err
		}
		size, err := r.u16()
		if err != nil {
			return err
		}
		data, err := r.bytes(int(size))
		if err != nil {
			return err
		}
		text := string(data)
		if idx == 0xFFFFFFFF {
			arc.Comment = text
		} else if int(idx) < len(arc.Files) {
			arc.Files[idx].Comment = text
		}
		remaining -= int64(6 + len(data))
	}
	return nil
}

func readSizedInt(r *reader, size int) (uint64, error) {
	data, err := r.bytes(size)
	if err != nil {
		return 0, err
	}
	switch size {
	case 1:
		return uint64(data[0]), nil
	case 2:
		return uint64(binary.LittleEndian.Uint16(data)), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(data)), nil
	case 8:
		return binary.LittleEndian.Uint64(data), nil
	default:
		return 0, fmt.Errorf("alz: invalid integer size %d", size)
	}
}

func decodeName(raw []byte) (string, error) {
	if utf8.Valid(raw) {
		return string(raw), nil
	}
	decoded, _, err := transform.Bytes(korean.EUCKR.NewDecoder(), raw)
	if err != nil {
		// fall back to raw bytes if decode fails
		return string(raw), nil
	}
	return string(decoded), nil
}

func cleanPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Clean(name)
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimPrefix(name, "/")
	return name
}

func mapAttributes(attr byte) uint32 {
	var result uint32
	if attr&0x01 != 0 {
		result |= 0x01 // FILE_ATTRIBUTE_READONLY
	}
	if attr&0x02 != 0 {
		result |= 0x02 // HIDDEN
	}
	if attr&0x04 != 0 {
		result |= 0x04 // SYSTEM
	}
	if attr&0x10 != 0 {
		result |= FileAttributeDirectory
	}
	return result
}

func dosTimeToTime(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	date := v >> 16
	timePart := v & 0xFFFF
	year := int((date>>9)&0x7F) + 1980
	month := time.Month((date >> 5) & 0x0F)
	day := int(date & 0x1F)
	hour := int((timePart >> 11) & 0x1F)
	min := int((timePart >> 5) & 0x3F)
	sec := int(timePart&0x1F) * 2

	if month < 1 || month > 12 || day < 1 || day > 31 {
		return time.Time{}
	}

	return time.Date(year, month, day, hour, min, sec, 0, time.Local)
}

func readEndInfos(r io.ReaderAt, size int64) ([4]uint32, error) {
	var out [4]uint32
	buf := make([]byte, 16)
	if _, err := r.ReadAt(buf, size-16); err != nil {
		return out, err
	}
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint32(buf[i*4:])
	}
	return out, nil
}

type segment struct {
	f      *os.File
	offset int64
	size   int64
}

func buildReader(path string) (io.ReaderAt, int64, func(), bool, error) {
	seg, multi, err := openSegments(path)
	if err != nil {
		return nil, 0, nil, false, err
	}
	if len(seg) == 1 {
		f := seg[0].f
		return f, seg[0].size, func() { _ = f.Close() }, multi, nil
	}
	cr := newConcatReader(seg)
	return cr, cr.size, cr.Close, multi, nil
}

func openSegments(firstPath string) ([]segment, bool, error) {
	var segs []segment

	add := func(p string, offset int64, trimTail int64) error {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		if offset < 0 || offset > st.Size() {
			offset = 0
		}
		size := st.Size() - offset
		if trimTail > 0 && trimTail < size {
			size -= trimTail
		}
		segs = append(segs, segment{f: f, offset: offset, size: size})
		return nil
	}

	// Check if there are additional segments (.a00, .a01, etc.)
	base := strings.TrimSuffix(firstPath, filepath.Ext(firstPath))
	firstNext := fmt.Sprintf("%s.a%02d", base, 0)
	_, hasMoreSegments := os.Stat(firstNext)

	// First segment: if split archive, trim 16-byte CLZ trailer
	firstTrimTail := int64(0)
	if hasMoreSegments == nil {
		firstTrimTail = 16
	}
	if err := add(firstPath, 0, firstTrimTail); err != nil {
		return nil, false, err
	}

	for i := 0; ; i++ {
		next := fmt.Sprintf("%s.a%02d", base, i)
		if _, err := os.Stat(next); err != nil {
			break
		}
		offset, trimTail := detectSplitOffset(next)
		if err := add(next, offset, trimTail); err != nil {
			return nil, false, err
		}
	}

	return segs, len(segs) > 1, nil
}

func detectSplitOffset(path string) (offset int64, trimTail int64) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var sig uint32
	if err := binary.Read(io.NewSectionReader(f, 0, 4), binary.LittleEndian, &sig); err != nil {
		return 0, 0
	}
	if sig == SignatureAlzHeader {
		// Split ALZ segment: 8-byte header (sig + version + id), 16-byte CLZ trailer
		return 8, 16
	}
	return 0, 0
}

type concatReader struct {
	segs []segment
	size int64
}

func newConcatReader(segs []segment) *concatReader {
	var total int64
	for _, s := range segs {
		total += s.size
	}
	return &concatReader{segs: segs, size: total}
}

func (c *concatReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("alz: invalid offset")
	}
	if off >= c.size {
		return 0, io.EOF
	}
	readTotal := 0
	curOff := off
	remain := p
	for _, s := range c.segs {
		if curOff >= s.size {
			curOff -= s.size
			continue
		}
		toRead := int64(len(remain))
		if curOff+toRead > s.size {
			toRead = s.size - curOff
		}
		n, err := s.f.ReadAt(remain[:toRead], s.offset+curOff)
		readTotal += n
		remain = remain[n:]
		if err != nil {
			if errors.Is(err, io.EOF) && len(remain) == 0 {
				return readTotal, nil
			}
			return readTotal, err
		}
		curOff = 0
		if len(remain) == 0 {
			break
		}
	}
	if len(remain) > 0 {
		return readTotal, io.EOF
	}
	return readTotal, nil
}

func (c *concatReader) Close() {
	for _, s := range c.segs {
		_ = s.f.Close()
	}
}

type reader struct {
	r    io.ReaderAt
	off  int64
	size int64
}

func (r *reader) pos() int64 { return r.off }

func (r *reader) u8() (byte, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) u16() (uint16, error) {
	b, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *reader) u32() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("alz: invalid read length %d", n)
	}
	if r.off+int64(n) > r.size {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	_, err := r.r.ReadAt(buf, r.off)
	if err != nil {
		return nil, err
	}
	r.off += int64(n)
	return buf, nil
}

func (r *reader) skip(n int64) error {
	if r.off+n < 0 || r.off+n > r.size {
		return io.ErrUnexpectedEOF
	}
	r.off += n
	return nil
}
