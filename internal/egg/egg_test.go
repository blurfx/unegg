package egg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// simple archive example from the spec
const sampleSimpleHex = "" +
	"45 47 47 41 00 01 01 00 00 00 00 00 00 00 22 82 E2 08 " +
	"E3 90 85 0A 00 00 00 00 05 00 00 00 00 00 00 00 22 82 E2 08 " +
	"13 0C B5 02 00 00 05 00 00 00 05 00 00 00 86 A6 10 36 22 82 E2 08 " +
	"68 65 6C 6C 6F " +
	"22 82 E2 08"

// general file archive example from the spec
const sampleGeneralHex = "" +
	"45 47 47 41 00 01 01 00 00 00 00 00 00 00 22 82 E2 08 " + // egg header
	"E3 90 85 0A 00 00 00 00 05 00 00 00 00 00 00 00 " + // file header
	"AC 91 85 0A 00 09 00 68 65 6C 6C 6F 2E 74 78 74 " + // filename "hello.txt"
	"0B 95 86 2C 00 09 00 23 C9 A3 4F 63 FB C7 01 00 " + // windows file info
	"22 82 E2 08 " + // end of file header
	"13 0C B5 02 00 00 05 00 00 00 05 00 00 00 86 A6 10 36 " + // block header (store)
	"22 82 E2 08 " + // end of block header
	"68 65 6C 6C 6F " + // data
	"22 82 E2 08" // end of archive

// encrypted archive example
const sampleEncryptedHex = "" +
	"45 47 47 41 00 01 01 00 00 00 00 00 00 00 22 82 E2 08 " + // egg header
	"E3 90 85 0A 00 00 00 00 01 00 00 00 00 00 00 00 " + // file header, size 1
	"AC 91 85 0A 00 01 00 78 " + // filename "x"
	"0F 47 D1 08 00 11 00 00 " + // encrypt header (magic, flag, size=17, method=0)
	"01 02 03 04 05 06 07 08 09 0A 0B 0C " + // verify
	"00 00 00 00 " + // crc
	"22 82 E2 08 " + // end of file header
	"13 0C B5 02 00 00 01 00 00 00 01 00 00 00 00 00 00 00 " + // block header (store, crc 0)
	"22 82 E2 08 " + // end of block header
	"78 " + // data
	"22 82 E2 08" // end of archive

// first part of the spec's split example (not supported yet)
const sampleSplitHex = "" +
	"45 47 47 41 00 01 01 00 00 00 00 00 00 00 " + // egg header
	"62 A2 F5 24 00 08 00 00 00 00 00 02 00 00 00" // split header with next id=2

func writeSampleEgg(t *testing.T, path string) {
	t.Helper()
	writeHex(t, path, sampleSimpleHex)
}

func buildZipCryptoEgg(password, name string, data []byte) ([]byte, error) {
	var buf bytes.Buffer

	crc := crc32.ChecksumIEEE(data)
	verifyPlain := make([]byte, 12)
	verifyPlain[11] = byte(crc >> 24)

	enc := newZipEncryptor(password)
	verifyEnc := enc.encryptBytes(verifyPlain)
	cipherData := enc.encryptBytes(data)

	// EGG header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEggHeader))
	binary.Write(&buf, binary.LittleEndian, uint16(0x0100)) // version
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // program id
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // reserved
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// File header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFile))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // index
	binary.Write(&buf, binary.LittleEndian, uint64(len(data)))

	// filename extra
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFilename))
	buf.WriteByte(expectedExtraFlag)
	binary.Write(&buf, binary.LittleEndian, uint16(len(name)))
	buf.WriteString(name)

	// encryption extra
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEncrypt))
	buf.WriteByte(expectedExtraFlag)
	binary.Write(&buf, binary.LittleEndian, uint16(17)) // size includes method byte
	buf.WriteByte(0)                                    // method: ZipCrypto
	buf.Write(verifyEnc)
	binary.Write(&buf, binary.LittleEndian, crc)

	// end of file header extras
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// block header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureBlock))
	buf.WriteByte(0)                                                 // method store
	buf.WriteByte(0)                                                 // hint
	binary.Write(&buf, binary.LittleEndian, uint32(len(data)))       // unpack
	binary.Write(&buf, binary.LittleEndian, uint32(len(cipherData))) // pack
	binary.Write(&buf, binary.LittleEndian, crc)                     // crc of plaintext
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// block data (encrypted)
	buf.Write(cipherData)

	// end of archive
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	return buf.Bytes(), nil
}

type zipEncryptor struct {
	keys [3]uint32
}

func newZipEncryptor(password string) *zipEncryptor {
	z := &zipEncryptor{}
	z.keys[0] = 0x12345678
	z.keys[1] = 0x23456789
	z.keys[2] = 0x34567890
	for i := 0; i < len(password); i++ {
		z.updateKeys(password[i])
	}
	return z
}

func (z *zipEncryptor) updateKeys(b byte) {
	z.keys[0] = crc32ZipUpdate(z.keys[0], b)
	z.keys[1] = (z.keys[1]+(z.keys[0]&0xff))*0x8088405 + 1
	z.keys[2] = crc32ZipUpdate(z.keys[2], byte(z.keys[1]>>24))
}

func (z *zipEncryptor) decryptByte() byte {
	tmp := z.keys[2] | 2
	return byte((tmp * (tmp ^ 1)) >> 8)
}

func (z *zipEncryptor) encryptBytes(plain []byte) []byte {
	out := make([]byte, len(plain))
	for i := range plain {
		ks := z.decryptByte()
		out[i] = plain[i] ^ ks
		z.updateKeys(plain[i])
	}
	return out
}

func writeHex(t *testing.T, path, hexStr string) {
	t.Helper()
	fields := strings.Fields(hexStr)
	buf := make([]byte, len(fields))
	for i, f := range fields {
		b, err := hex.DecodeString(f)
		if err != nil {
			t.Fatalf("decode hex: %v", err)
		}
		buf[i] = b[0]
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
}

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", name)
}

func buildSolidSample() []byte {
	var buf bytes.Buffer
	// EGG header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEggHeader))
	binary.Write(&buf, binary.LittleEndian, uint16(0x0100))
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // program id
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // reserved

	// solid header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureSolid))
	buf.WriteByte(expectedExtraFlag)
	binary.Write(&buf, binary.LittleEndian, uint16(0))

	// end of egg header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// file a.txt (size 1)
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFile))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint64(1))
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFilename))
	buf.WriteByte(expectedExtraFlag)
	binary.Write(&buf, binary.LittleEndian, uint16(len("a.txt")))
	buf.WriteString("a.txt")
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// file b.txt (size 2)
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFile))
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	binary.Write(&buf, binary.LittleEndian, uint64(2))
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFilename))
	buf.WriteByte(expectedExtraFlag)
	binary.Write(&buf, binary.LittleEndian, uint16(len("b.txt")))
	buf.WriteString("b.txt")
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// solid block holding "abc"
	data := []byte("abc")
	blockCRC := crc32.ChecksumIEEE(data)
	binary.Write(&buf, binary.LittleEndian, uint32(signatureBlock))
	buf.WriteByte(0) // method store
	buf.WriteByte(0) // hint
	binary.Write(&buf, binary.LittleEndian, uint32(len(data)))
	binary.Write(&buf, binary.LittleEndian, uint32(len(data)))
	binary.Write(&buf, binary.LittleEndian, blockCRC)
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))
	buf.Write(data)

	// end of archive
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))
	return buf.Bytes()
}

func TestParseSimpleArchive(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "simple.egg")
	writeSampleEgg(t, eggPath)

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if arc.Version != 0x0100 {
		t.Fatalf("version = %x, want 0x0100", arc.Version)
	}
	if arc.ProgramID != 1 {
		t.Fatalf("program id = %d, want 1", arc.ProgramID)
	}
	if len(arc.Files) != 1 {
		t.Fatalf("files len = %d, want 1", len(arc.Files))
	}
	f := arc.Files[0]
	if f.Size != 5 {
		t.Fatalf("file size = %d, want 5", f.Size)
	}
	if len(f.Blocks) != 1 {
		t.Fatalf("blocks len = %d, want 1", len(f.Blocks))
	}
	b := f.Blocks[0]
	if b.Method != 0 {
		t.Fatalf("block method = %d, want 0 (store)", b.Method)
	}
	if b.UnpackSize != 5 {
		t.Fatalf("block unpack = %d, want 5", b.UnpackSize)
	}
}

func TestExtractSimpleArchive(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "simple.egg")
	writeSampleEgg(t, eggPath)

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true, Concurrency: 2}); err != nil {
		t.Fatalf("extract: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dest, "00000000"))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("extracted content = %q, want %q", data, "hello")
	}
}

func TestParseGeneralArchive(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "general.egg")
	writeHex(t, eggPath, sampleGeneralHex)

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := len(arc.Files), 1; got != want {
		t.Fatalf("files len = %d, want %d", got, want)
	}
	f := arc.Files[0]
	if f.Path != "hello.txt" {
		t.Fatalf("filename = %q, want %q", f.Path, "hello.txt")
	}
	if f.ModTime.IsZero() {
		t.Fatalf("mod time should be present")
	}
	if len(f.Blocks) != 1 {
		t.Fatalf("blocks len = %d, want 1", len(f.Blocks))
	}
}

func TestParseEncryptedArchive(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "encrypted.egg")
	writeHex(t, eggPath, sampleEncryptedHex)

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := len(arc.Files), 1; got != want {
		t.Fatalf("files len = %d, want %d", got, want)
	}
	if arc.Files[0].Encryption == nil {
		t.Fatalf("encryption info missing")
	}
	if arc.Files[0].Encryption.Method != 0 {
		t.Fatalf("encryption method = %d, want 0 (ZipCrypto)", arc.Files[0].Encryption.Method)
	}
}

func TestParseSplitArchiveFails(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "split.egg")
	writeHex(t, eggPath, sampleSplitHex)

	// TODO: support split archives
	if _, err := Parse(eggPath); err == nil || err != ErrUnsupportedSplit {
		t.Fatalf("parse error = %v, want ErrUnsupportedSplit", err)
	}
}

func TestExtractZipCryptoArchive(t *testing.T) {
	password := "pw"
	name := "secret.txt"
	plaintext := []byte("s")

	data, err := buildZipCryptoEgg(password, name, plaintext)
	if err != nil {
		t.Fatalf("build sample: %v", err)
	}

	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "zipcrypto.egg")
	if err := os.WriteFile(eggPath, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Password: password, Quiet: true, Concurrency: 1}); err != nil {
		t.Fatalf("extract: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, name))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("extracted = %q, want %q", got, plaintext)
	}
}

func TestExtractProvidedTestdata(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{name: "unegg.egg", password: ""},
		{name: "unegg.1234.egg", password: "1234"},
		{name: "unegg.1q2w3e4r!.egg", password: "1q2w3e4r!"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			arc, err := Parse(testdataPath(tc.name))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			dest := t.TempDir()
			err = arc.ExtractAll(ExtractOptions{Dest: dest, Password: tc.password, Quiet: true, Concurrency: 1})
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(dest, "unegg.txt"))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(data) != "unegg" {
				t.Fatalf("content = %q, want %q", data, "unegg")
			}
		})
	}
}

func TestExtractSolidArchiveSynthetic(t *testing.T) {
	buf := buildSolidSample()
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "solid.egg")
	if err := os.WriteFile(eggPath, buf, 0o644); err != nil {
		t.Fatalf("write solid sample: %v", err)
	}

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !arc.IsSolid {
		t.Fatalf("expected solid archive flag")
	}

	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true}); err != nil {
		t.Fatalf("extract: %v", err)
	}

	gotA, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatalf("read a.txt: %v", err)
	}
	gotB, err := os.ReadFile(filepath.Join(dest, "b.txt"))
	if err != nil {
		t.Fatalf("read b.txt: %v", err)
	}
	if string(gotA) != "a" || string(gotB) != "bc" {
		t.Fatalf("extracted content = %q, %q; want %q, %q", gotA, gotB, "a", "bc")
	}
}

func TestSecureJoin(t *testing.T) {
	base := t.TempDir()

	got, err := secureJoin(base, "nested/file.txt")
	if err != nil {
		t.Fatalf("secureJoin valid err: %v", err)
	}
	want := filepath.Join(base, "nested/file.txt")
	if got != want {
		t.Fatalf("secureJoin valid = %q, want %q", got, want)
	}

	if _, err := secureJoin(base, "/abs/path"); err == nil {
		t.Fatalf("secureJoin abs path should error")
	}
	if _, err := secureJoin(base, "../escape"); err == nil {
		t.Fatalf("secureJoin traversal should error")
	}
}
