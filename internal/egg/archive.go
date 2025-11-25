package egg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	signatureEggHeader            = 0x41474745
	signatureSplit                = 0x24F5A262
	signatureSolid                = 0x24E5A060
	signatureFile                 = 0x0A8590E3
	signatureFilename             = 0x0A8591AC
	signatureComment              = 0x04C63672
	signatureWindowsFileInfo      = 0x2C86950B
	signatureEncrypt              = 0x08D1470F
	signatureBlock                = 0x02B50C13
	signatureDummy                = 0x07463307
	signatureSkip                 = 0xFFFF0000
	signatureEnd                  = 0x08E28222
	FileAttributeDirectory        = 0x10
	expectedExtraFlag        byte = 0x00
)

var (
	ErrBadSignature     = errors.New("egg: invalid signature")
	ErrUnsupportedSplit = errors.New("egg: split archives are not supported (start from first volume)")
	ErrUnsupportedSolid = errors.New("egg: solid archives are not supported")
)

type Archive struct {
	ProgramID   uint32
	Version     uint16
	IsSolid     bool
	SplitBefore uint32
	SplitAfter  uint32
	Comment     string
	Files       []File
	path        string
	size        int64
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

func Parse(path string) (*Archive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	r := &reader{r: f, size: info.Size()}
	arc := &Archive{path: path, size: info.Size()}

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
			if prev != 0 || next != 0 {
				return ErrUnsupportedSplit
			}
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
			return ErrUnsupportedSolid
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
			file, err := parseFile(r)
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
		case signatureEnd:
			return nil
		default:
			return fmt.Errorf("egg: unknown signature 0x%x while reading files", sig)
		}
	}
}

func parseFile(r *reader) (*File, error) {
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
		case signatureEnd:
			goto Blocks
		default:
			return nil, fmt.Errorf("egg: unknown signature 0x%x in file extras", sig)
		}
	}

Blocks:
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
			f.Blocks = append(f.Blocks, *block)
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
