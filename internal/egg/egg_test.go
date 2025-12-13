package egg

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blurfx/unegg/internal/archive"
	"github.com/blurfx/unegg/internal/crypto"
)

type sampleFile struct {
	name      string
	data      []byte
	method    byte
	encrypted bool
	password  string
	modTime   time.Time
}

func buildEggArchive(t *testing.T, file sampleFile) []byte {
	t.Helper()

	var buf bytes.Buffer
	packed := file.data
	crc := crc32.ChecksumIEEE(file.data)

	// EGG header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEggHeader))
	binary.Write(&buf, binary.LittleEndian, uint16(0x0100)) // version
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // program id
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // reserved
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// File header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFile))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // index
	binary.Write(&buf, binary.LittleEndian, uint64(len(file.data)))

	// Filename extra (if name provided)
	if file.name != "" {
		binary.Write(&buf, binary.LittleEndian, uint32(signatureFilename))
		buf.WriteByte(expectedExtraFlag)
		binary.Write(&buf, binary.LittleEndian, uint16(len(file.name)))
		buf.WriteString(file.name)
	}

	// Windows file info extra (if modTime provided)
	if !file.modTime.IsZero() {
		binary.Write(&buf, binary.LittleEndian, uint32(signatureWindowsFileInfo))
		buf.WriteByte(expectedExtraFlag)
		binary.Write(&buf, binary.LittleEndian, uint16(9)) // size: 8 bytes filetime + 1 byte attr
		// Convert to Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
		const windowsToUnixOffset = 116444736000000000
		ft := uint64(file.modTime.UnixNano()/100) + windowsToUnixOffset
		binary.Write(&buf, binary.LittleEndian, ft)
		buf.WriteByte(0x00) // attributes
	}

	// Encryption extra
	var verifyEnc []byte
	if file.encrypted {
		verifyPlain := make([]byte, 12)
		verifyPlain[11] = byte(crc >> 24)

		enc := crypto.NewZipEncryptor(file.password)
		verifyEnc = enc.EncryptBytes(verifyPlain)
		packed = enc.EncryptBytes(file.data)

		binary.Write(&buf, binary.LittleEndian, uint32(signatureEncrypt))
		buf.WriteByte(expectedExtraFlag)
		binary.Write(&buf, binary.LittleEndian, uint16(17)) // size: 1 method + 12 verify + 4 crc
		buf.WriteByte(0)                                    // method: ZipCrypto
		buf.Write(verifyEnc)
		binary.Write(&buf, binary.LittleEndian, crc)
	}

	// End of file header extras
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// Block header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureBlock))
	buf.WriteByte(file.method)                                   // method (0=store)
	buf.WriteByte(0)                                             // hint
	binary.Write(&buf, binary.LittleEndian, uint32(len(packed))) // unpack size
	binary.Write(&buf, binary.LittleEndian, uint32(len(packed))) // pack size
	binary.Write(&buf, binary.LittleEndian, crc)
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	// Block data
	buf.Write(packed)

	// End of archive
	binary.Write(&buf, binary.LittleEndian, uint32(signatureEnd))

	return buf.Bytes()
}

func writeSampleEgg(t *testing.T, path string) {
	t.Helper()
	data := buildEggArchive(t, sampleFile{data: []byte("hello"), method: 0})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
}

func buildZipCryptoEgg(password, name string, data []byte) ([]byte, error) {
	var buf bytes.Buffer

	crc := crc32.ChecksumIEEE(data)
	verifyPlain := make([]byte, 12)
	verifyPlain[11] = byte(crc >> 24)

	enc := crypto.NewZipEncryptor(password)
	verifyEnc := enc.EncryptBytes(verifyPlain)
	cipherData := enc.EncryptBytes(data)

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

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "egg", name)
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
	modTime := time.Date(2020, 1, 15, 10, 30, 0, 0, time.UTC)
	data := buildEggArchive(t, sampleFile{
		name:    "hello.txt",
		data:    []byte("hello"),
		method:  0,
		modTime: modTime,
	})
	if err := os.WriteFile(eggPath, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

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
	data := buildEggArchive(t, sampleFile{
		name:      "x",
		data:      []byte("x"),
		method:    0,
		encrypted: true,
		password:  "test",
	})
	if err := os.WriteFile(eggPath, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

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

func TestExtractZipCryptoArchive(t *testing.T) {
	password := "pw"
	name := "secret.txt"
	plaintext := []byte("s")

	data := buildEggArchive(t, sampleFile{
		name:      name,
		data:      plaintext,
		method:    0,
		encrypted: true,
		password:  password,
	})

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
		{name: "normal.egg", password: ""},
		{name: "encrypted.1q2w3e4r!.egg", password: "1q2w3e4r!"},
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

func TestExtractSplitArchives(t *testing.T) {
	cases := []string{
		"split.nocompress.vol1.egg",
		"split.high.vol1.egg",
	}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			arc, err := Parse(testdataPath(name))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			dest := t.TempDir()
			if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true}); err != nil {
				t.Fatalf("extract: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(dest, "data.txt"))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(data) == 0 {
				t.Fatalf("empty extracted data")
			}
			if strings.Contains(name, "nocompress") && !bytes.HasPrefix(data, []byte("0123456789")) {
				t.Fatalf("unexpected data prefix")
			}
		})
	}
}

func TestUnicodeEmojiArchive(t *testing.T) {
	archiveName := "미즈노아미水野亜美マーキュリー🌈🌕🌊.egg"
	arc, err := Parse(testdataPath(archiveName))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(arc.Files) != 1 {
		t.Fatalf("files len = %d, want 1", len(arc.Files))
	}
	wantName := "미즈노아미水野亜美マーキュリー🌈🌕🌊.txt"
	if arc.Files[0].Path != wantName {
		t.Fatalf("filename = %q, want %q", arc.Files[0].Path, wantName)
	}

	dest := t.TempDir()
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, wantName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(content) != "미즈노아미水野亜美マーキュリー🌈🌕🌊" {
		t.Fatalf("content = %q", content)
	}
}

func TestSecureJoin(t *testing.T) {
	base := t.TempDir()

	got, err := archive.SecureJoin(base, "nested/file.txt")
	if err != nil {
		t.Fatalf("archive.SecureJoin valid err: %v", err)
	}
	want := filepath.Join(base, "nested/file.txt")
	if got != want {
		t.Fatalf("archive.SecureJoin valid = %q, want %q", got, want)
	}

	if _, err := archive.SecureJoin(base, "/abs/path"); err == nil {
		t.Fatalf("archive.SecureJoin abs path should error")
	}
	if _, err := archive.SecureJoin(base, "../escape"); err == nil {
		t.Fatalf("archive.SecureJoin traversal should error")
	}
}
