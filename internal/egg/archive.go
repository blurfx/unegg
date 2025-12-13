package egg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blurfx/unegg/internal/archive"
)

// Internal format signatures.
const (
	signatureEggHeader       = 0x41474745 // "EGGA"
	signatureSplit           = 0x24F5A262
	signatureSolid           = 0x24E5A060
	signatureFile            = 0x0A8590E3
	signatureFilename        = 0x0A8591AC
	signatureComment         = 0x04C63672
	signatureWindowsFileInfo = 0x2C86950B
	signatureEncrypt         = 0x08D1470F
	signatureBlock           = 0x02B50C13
	signatureSkip            = 0xFFFF0000
	signatureEnd             = 0x08E28222
	expectedExtraFlag        = 0x00
)

// SignatureHeader is the EGG archive magic number (exported for format detection).
const SignatureHeader = signatureEggHeader

// FileAttributeDirectory indicates a directory entry in file attributes.
const FileAttributeDirectory = 0x10

// Package errors.
var (
	// ErrBadSignature indicates the file is not a valid EGG archive.
	ErrBadSignature = archive.ErrBadSignature

	// ErrUnsupportedSplit indicates a split archive volume other than the first.
	ErrUnsupportedSplit = errors.New("egg: split archives are not supported (start from first volume)")
)

type Archive struct {
	ProgramID   uint32
	Version     uint16
	IsSolid     bool
	SplitBefore uint32
	SplitAfter  uint32
	Comment     string
	Files       []File
	SolidBlocks []Block
	path        string
	size        int64
	reader      io.ReaderAt
}

type File struct {
	Index      uint32
	Size       uint64
	Path       string
	Comment    string
	Attributes uint32
	ModTime    time.Time
	Blocks     []Block
	Encryption *EncryptionInfo
}

type Block struct {
	Method     byte
	Hint       byte
	UnpackSize uint32
	PackSize   uint32
	CRC        uint32
	Offset     int64
}

type EncryptionInfo struct {
	Method byte

	// ZipCrypto
	ZipVerify []byte
	ZipCRC    uint32

	// AES / LEA (LEA not implemented)
	Salt []byte
	Mac  []byte
}

type splitVolume struct {
	file       *os.File
	dataOffset int64
	size       int64
}

func Parse(path string) (*Archive, error) {
	readerAt, size, err := buildReader(path)
	if err != nil {
		return nil, err
	}
	r := &reader{r: readerAt, size: size}
	arc := &Archive{path: path, size: size}
	if _, ok := readerAt.(*os.File); !ok {
		arc.reader = readerAt
	}

	sig, err := r.u32()
	if err != nil {
		return nil, err
	}
	if sig != signatureEggHeader {
		return nil, ErrBadSignature
	}

	version, err := r.u16()
	if err != nil {
		return nil, err
	}
	arc.Version = version
	program, err := r.u32()
	if err != nil {
		return nil, err
	}
	arc.ProgramID = program
	if _, err := r.u32(); err != nil { // reserved
		return nil, err
	}

	if err := arc.parsePrefix(r); err != nil {
		return nil, err
	}
	if err := arc.parseFiles(r); err != nil {
		return nil, err
	}

	return arc, nil
}

func buildReader(firstPath string) (io.ReaderAt, int64, error) {
	segments, err := buildSplitSegments(firstPath)
	if err == nil && len(segments) > 0 {
		cr := newConcatReader(segments)
		return cr, cr.size, nil
	}

	// fallback to single file
	f, err := os.Open(firstPath)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

type volumeInfo struct {
	programID  uint32
	prev       uint32
	next       uint32
	dataOffset int64
}

func buildSplitSegments(firstPath string) ([]splitVolume, error) {
	info, err := readVolumeInfo(firstPath)
	if err != nil {
		return nil, err
	}
	if info.prev == 0 && info.next == 0 {
		return nil, ErrUnsupportedSplit
	}

	var vols []splitVolume
	appendVol := func(path string, vi volumeInfo) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		stat, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		offset := vi.dataOffset
		length := stat.Size() - offset
		if len(vols) == 0 {
			offset = 0
			length = stat.Size()
		}
		if length < 0 {
			return fmt.Errorf("egg: invalid split volume length")
		}
		vols = append(vols, splitVolume{file: f, dataOffset: offset, size: length})
		return nil
	}

	if err := appendVol(firstPath, info); err != nil {
		return nil, err
	}

	expectedPrev := info.programID
	nextID := info.next
	currentPath := firstPath
	for nextID != 0 {
		nextPath, ok := incrementVolumePath(currentPath)
		if !ok {
			return nil, fmt.Errorf("egg: cannot find next split volume after %s", currentPath)
		}
		vi, err := readVolumeInfo(nextPath)
		if err != nil {
			return nil, fmt.Errorf("egg: read split volume %s: %w", nextPath, err)
		}
		if vi.prev != expectedPrev {
			return nil, fmt.Errorf("egg: split volume chain mismatch (prev=%x expected=%x)", vi.prev, expectedPrev)
		}
		if err := appendVol(nextPath, vi); err != nil {
			return nil, err
		}
		currentPath = nextPath
		expectedPrev = vi.programID
		nextID = vi.next
	}
	return vols, nil
}

func readVolumeInfo(p string) (volumeInfo, error) {
	var vi volumeInfo
	f, err := os.Open(p)
	if err != nil {
		return vi, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return vi, err
	}
	r := &reader{r: f, size: stat.Size()}

	sig, err := r.u32()
	if err != nil {
		return vi, err
	}
	if sig != signatureEggHeader {
		return vi, ErrBadSignature
	}
	if _, err := r.u16(); err != nil { // version
		return vi, err
	}
	prog, err := r.u32()
	if err != nil {
		return vi, err
	}
	vi.programID = prog
	if _, err := r.u32(); err != nil { // reserved
		return vi, err
	}

	for {
		sig, err := r.u32()
		if err != nil {
			return vi, err
		}
		switch sig {
		case signatureSplit:
			flag, err := r.u8()
			if err != nil {
				return vi, err
			}
			if flag != expectedExtraFlag {
				return vi, fmt.Errorf("egg: unexpected split flag %x", flag)
			}
			if _, err := r.u16(); err != nil { // size
				return vi, err
			}
			prev, err := r.u32()
			if err != nil {
				return vi, err
			}
			next, err := r.u32()
			if err != nil {
				return vi, err
			}
			vi.prev, vi.next = prev, next
		case signatureSolid:
			flag, err := r.u8()
			if err != nil {
				return vi, err
			}
			if flag != expectedExtraFlag {
				return vi, fmt.Errorf("egg: unexpected solid flag %x", flag)
			}
			size, err := r.u16()
			if err != nil {
				return vi, err
			}
			if size != 0 {
				return vi, fmt.Errorf("egg: unexpected solid payload of size %d", size)
			}
		case signatureSkip:
			flag, err := r.u8()
			if err != nil {
				return vi, err
			}
			if flag != expectedExtraFlag {
				return vi, fmt.Errorf("egg: unexpected skip flag %x", flag)
			}
			sz, err := r.u16()
			if err != nil {
				return vi, err
			}
			if err := r.skip(int64(sz)); err != nil {
				return vi, err
			}
		case signatureEnd:
			vi.dataOffset = r.off
			return vi, nil
		default:
			return vi, fmt.Errorf("egg: unknown prefix signature 0x%x", sig)
		}
	}
}

func incrementVolumePath(p string) (string, bool) {
	dir, base := filepath.Split(p)
	re := regexp.MustCompile(`^(.*)vol(\d+)(.*)$`)
	m := re.FindStringSubmatch(base)
	if len(m) == 0 {
		return "", false
	}
	prefix, numStr, suffix := m[1], m[2], m[3]
	var num int
	if _, err := fmt.Sscanf(numStr, "%d", &num); err != nil {
		return "", false
	}
	next := fmt.Sprintf("%svol%d%s", prefix, num+1, suffix)
	return filepath.Join(dir, next), true
}

type concatReader struct {
	segs []splitVolume
	size int64
}

func newConcatReader(segs []splitVolume) *concatReader {
	var total int64
	for _, s := range segs {
		total += s.size
	}
	return &concatReader{segs: segs, size: total}
}

func (c *concatReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("egg: invalid offset")
	}
	if off >= c.size {
		return 0, io.EOF
	}
	readTotal := 0
	remain := p
	curOff := off
	for _, s := range c.segs {
		if curOff >= s.size {
			curOff -= s.size
			continue
		}
		toRead := int64(len(remain))
		if curOff+toRead > s.size {
			toRead = s.size - curOff
		}
		n, err := s.file.ReadAt(remain[:toRead], s.dataOffset+curOff)
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

func (a *Archive) parsePrefix(r *reader) error {
	for {
		sig, err := r.u32()
		if err != nil {
			return err
		}
		switch sig {
		case signatureSplit:
			flag, err := r.u8()
			if err != nil {
				return err
			}
			if flag != expectedExtraFlag {
				return fmt.Errorf("egg: unexpected split flag %x", flag)
			}
			if _, err := r.u16(); err != nil { // size
				return err
			}
			prev, err := r.u32()
			if err != nil {
				return err
			}
			next, err := r.u32()
			if err != nil {
				return err
			}
			a.SplitBefore, a.SplitAfter = prev, next
		case signatureSolid:
			flag, err := r.u8()
			if err != nil {
				return err
			}
			if flag != expectedExtraFlag {
				return fmt.Errorf("egg: unexpected solid flag %x", flag)
			}
			size, err := r.u16()
			if err != nil {
				return err
			}
			if size != 0 {
				return fmt.Errorf("egg: unexpected solid payload of size %d", size)
			}
			a.IsSolid = true
		case signatureSkip:
			// Skip header: follows same shape as split, ignore payload.
			flag, err := r.u8()
			if err != nil {
				return err
			}
			if flag != expectedExtraFlag {
				return fmt.Errorf("egg: unexpected skip flag %x", flag)
			}
			size, err := r.u16()
			if err != nil {
				return err
			}
			if err := r.skip(int64(size)); err != nil {
				return err
			}
		case signatureEnd:
			return nil
		default:
			return fmt.Errorf("egg: unknown prefix signature 0x%x", sig)
		}
	}
}

func (a *Archive) parseFiles(r *reader) error {
	for {
		sig, err := r.u32()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return err
			}
			return err
		}
		switch sig {
		case signatureFile:
			file, err := parseFile(r, a.IsSolid, &a.SolidBlocks)
			if err != nil {
				return err
			}
			a.Files = append(a.Files, *file)
		case signatureComment:
			comment, err := parseComment(r)
			if err != nil {
				return err
			}
			a.Comment = comment
		case signatureBlock:
			if !a.IsSolid {
				return fmt.Errorf("egg: unexpected block at archive level")
			}
			block, err := parseBlock(r)
			if err != nil {
				return err
			}
			a.SolidBlocks = append(a.SolidBlocks, *block)
		case signatureEnd:
			return nil
		default:
			return fmt.Errorf("egg: unknown signature 0x%x while reading files", sig)
		}
	}
}

func parseFile(r *reader, solid bool, solidBlocks *[]Block) (*File, error) {
	idx, err := r.u32()
	if err != nil {
		return nil, err
	}
	size, err := r.u64()
	if err != nil {
		return nil, err
	}
	f := &File{Index: idx, Size: size}

	for {
		sig, err := r.u32()
		if err != nil {
			return nil, err
		}
		if sig == signatureEnd {
			break
		}
		switch sig {
		case signatureFilename:
			name, err := parseFilename(r)
			if err != nil {
				return nil, err
			}
			f.Path = name
		case signatureComment:
			comment, err := parseComment(r)
			if err != nil {
				return nil, err
			}
			f.Comment = comment
		case signatureWindowsFileInfo:
			info, err := parseWindowsFileInfo(r)
			if err != nil {
				return nil, err
			}
			f.Attributes = info.attributes
			f.ModTime = info.modTime
		case signatureEncrypt:
			enc, err := parseEncryption(r)
			if err != nil {
				return nil, err
			}
			f.Encryption = enc
		default:
			return nil, fmt.Errorf("egg: unknown signature 0x%x in file extras", sig)
		}
	}

	for {
		sig, err := r.u32()
		if err != nil {
			return nil, err
		}
		switch sig {
		case signatureBlock:
			block, err := parseBlock(r)
			if err != nil {
				return nil, err
			}
			if solid {
				*solidBlocks = append(*solidBlocks, *block)
			} else {
				f.Blocks = append(f.Blocks, *block)
			}
		case signatureComment, signatureFile, signatureEnd:
			// signature belongs to parent loop; rewind 4 bytes so caller sees it.
			if err := r.skip(-4); err != nil {
				return nil, err
			}
			return f, nil
		default:
			return nil, fmt.Errorf("egg: unknown signature 0x%x in block list", sig)
		}
	}
}

func parseFilename(r *reader) (string, error) {
	flag, err := r.u8()
	if err != nil {
		return "", err
	}
	if flag != expectedExtraFlag {
		return "", fmt.Errorf("egg: unexpected filename flag %x", flag)
	}
	size, err := r.u16()
	if err != nil {
		return "", err
	}
	data, err := r.bytes(int(size))
	if err != nil {
		return "", err
	}
	name := string(data)
	// normalize separators
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Clean(name)
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimPrefix(name, "/")
	return name, nil
}

func parseComment(r *reader) (string, error) {
	flag, err := r.u8()
	if err != nil {
		return "", err
	}
	if flag != expectedExtraFlag {
		return "", fmt.Errorf("egg: unexpected comment flag %x", flag)
	}
	size, err := r.u16()
	if err != nil {
		return "", err
	}
	data, err := r.bytes(int(size))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type winInfo struct {
	attributes uint32
	modTime    time.Time
}

func parseWindowsFileInfo(r *reader) (winInfo, error) {
	var info winInfo
	flag, err := r.u8()
	if err != nil {
		return info, err
	}
	if flag != expectedExtraFlag {
		return info, fmt.Errorf("egg: unexpected windows info flag %x", flag)
	}
	size, err := r.u16()
	if err != nil {
		return info, err
	}
	if size != 9 {
		return info, fmt.Errorf("egg: unexpected windows info size %d", size)
	}
	ftRaw, err := r.u64()
	if err != nil {
		return info, err
	}
	attr, err := r.u8()
	if err != nil {
		return info, err
	}

	const windowsToUnixOffset = 116444736000000000
	if ftRaw > windowsToUnixOffset {
		nanos := int64(ftRaw-windowsToUnixOffset) * 100
		info.modTime = time.Unix(0, nanos)
	}
	info.attributes = uint32(attr)
	return info, nil
}

func parseEncryption(r *reader) (*EncryptionInfo, error) {
	flag, err := r.u8()
	if err != nil {
		return nil, err
	}
	if flag != expectedExtraFlag {
		return nil, fmt.Errorf("egg: unexpected encryption flag %x", flag)
	}
	size, err := r.u16()
	if err != nil {
		return nil, err
	}
	method, err := r.u8()
	if err != nil {
		return nil, err
	}
	remaining := int(size) - 1
	if remaining < 0 {
		return nil, fmt.Errorf("egg: invalid encryption payload size %d", size)
	}
	enc := &EncryptionInfo{Method: method}
	switch method {
	case 0: // ZipCrypto
		if remaining != 16 {
			return nil, fmt.Errorf("egg: unexpected zip crypto payload size %d", remaining)
		}
		verify, err := r.bytes(12)
		if err != nil {
			return nil, err
		}
		crc, err := r.u32()
		if err != nil {
			return nil, err
		}
		enc.ZipVerify = verify
		enc.ZipCRC = crc
	case 1, 2, 5, 6: // AES/LEA
		var headerLen int
		switch method {
		case 1, 5:
			headerLen = 10
		case 2, 6:
			headerLen = 18
		}
		if remaining < headerLen+10 {
			return nil, fmt.Errorf("egg: encryption payload too small (%d)", remaining)
		}
		salt, err := r.bytes(headerLen)
		if err != nil {
			return nil, err
		}
		mac, err := r.bytes(10)
		if err != nil {
			return nil, err
		}
		enc.Salt = salt
		enc.Mac = mac
	default:
		return nil, fmt.Errorf("egg: unsupported encryption method %d", method)
	}
	return enc, nil
}

func parseBlock(r *reader) (*Block, error) {
	method, err := r.u8()
	if err != nil {
		return nil, err
	}
	hint, err := r.u8()
	if err != nil {
		return nil, err
	}
	unpack, err := r.u32()
	if err != nil {
		return nil, err
	}
	pack, err := r.u32()
	if err != nil {
		return nil, err
	}
	crc, err := r.u32()
	if err != nil {
		return nil, err
	}

	sig, err := r.u32()
	if err != nil {
		return nil, err
	}
	if sig != signatureEnd {
		return nil, fmt.Errorf("egg: missing end-of-block signature (got 0x%x)", sig)
	}

	offset := r.pos()
	if err := r.skip(int64(pack)); err != nil {
		return nil, err
	}

	return &Block{
		Method:     method,
		Hint:       hint,
		UnpackSize: unpack,
		PackSize:   pack,
		CRC:        crc,
		Offset:     offset,
	}, nil
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

func (r *reader) u64() (uint64, error) {
	b, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("egg: invalid read length %d", n)
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
