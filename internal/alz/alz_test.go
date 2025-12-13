package alz

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/blurfx/unegg/internal/crypto"
)

type sampleFile struct {
	name      string
	data      []byte
	method    uint16
	encrypted bool
	password  string
}

func buildAlzArchive(t *testing.T, file sampleFile) []byte {
	t.Helper()

	packed := file.data
	if file.method == 2 {
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.BestSpeed)
		if err != nil {
			t.Fatalf("deflate writer: %v", err)
		}
		if _, err := w.Write(file.data); err != nil {
			t.Fatalf("deflate write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("deflate close: %v", err)
		}
		packed = buf.Bytes()
	}

	crc := crc32.ChecksumIEEE(file.data)
	if len(file.data) == 0 {
		// keep crc consistent with decoder expectations
		crc = 0
	}

	var verify []byte
	if file.encrypted {
		enc := crypto.NewZipEncryptor(file.password)
		verifyPlain := make([]byte, 12)
		verifyPlain[11] = byte(crc >> 24)
		verify = enc.EncryptBytes(verifyPlain)
		packed = enc.EncryptBytes(packed)
	}

	sizeLen := sizeLenFor(len(packed), len(file.data))
	flags := uint16(sizeLen << 4)
	if file.encrypted {
		flags |= flagEncrypted
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(SignatureAlzHeader))
	binary.Write(&buf, binary.LittleEndian, uint16(0x0100)) // version
	binary.Write(&buf, binary.LittleEndian, uint16(0x0000)) // id

	// file header
	binary.Write(&buf, binary.LittleEndian, uint32(signatureFile))
	nameBytes := []byte(file.name)
	binary.Write(&buf, binary.LittleEndian, uint16(len(nameBytes)))
	buf.WriteByte(0x00)                                // attributes
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // datetime
	binary.Write(&buf, binary.LittleEndian, flags)
	binary.Write(&buf, binary.LittleEndian, file.method)
	binary.Write(&buf, binary.LittleEndian, crc)
	writeSizedInt(&buf, sizeLen, uint64(len(packed)))
	writeSizedInt(&buf, sizeLen, uint64(len(file.data)))

	buf.Write(nameBytes)
	if file.encrypted {
		buf.Write(verify)
	}
	buf.Write(packed)

	// footer: end signature + end info block
	const signatureEnd uint32 = 0x015A4C43
	binary.Write(&buf, binary.LittleEndian, signatureEnd)
	var endInfos [4]uint32
	for _, v := range endInfos {
		binary.Write(&buf, binary.LittleEndian, v)
	}

	return buf.Bytes()
}

func sizeLenFor(values ...int) int {
	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	switch {
	case max <= 0xFF:
		return 1
	case max <= 0xFFFF:
		return 2
	case max <= 0xFFFFFFFF:
		return 4
	default:
		return 8
	}
}

func writeSizedInt(buf *bytes.Buffer, size int, v uint64) {
	tmp := make([]byte, size)
	switch size {
	case 1:
		tmp[0] = byte(v)
	case 2:
		binary.LittleEndian.PutUint16(tmp, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(tmp, uint32(v))
	case 8:
		binary.LittleEndian.PutUint64(tmp, v)
	}
	buf.Write(tmp)
}

func TestParseAlzSimple(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "simple.alz")
	data := buildAlzArchive(t, sampleFile{name: "hello.txt", data: []byte("hi"), method: 0})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	arc, err := Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(arc.Files) != 1 {
		t.Fatalf("files len = %d, want 1", len(arc.Files))
	}
	f := arc.Files[0]
	if f.Name != "hello.txt" {
		t.Fatalf("filename = %q, want %q", f.Name, "hello.txt")
	}
	if f.Method != 0 || f.Size != 2 || f.PackSize != 2 {
		t.Fatalf("unexpected file info %+v", f)
	}
}

func TestExtractAlzStore(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "store.alz")
	data := buildAlzArchive(t, sampleFile{name: "a.txt", data: []byte("unegg"), method: 0})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	arc, err := Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true, Concurrency: 1}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(content) != "unegg" {
		t.Fatalf("content = %q, want %q", content, "unegg")
	}
}

func TestExtractAlzDeflate(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "deflate.alz")
	payload := bytes.Repeat([]byte("abc"), 10)
	data := buildAlzArchive(t, sampleFile{name: "b.txt", data: payload, method: 2})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	arc, err := Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true, Concurrency: 1}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "b.txt"))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("content mismatch")
	}
}

func TestExtractAlzEncrypted(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "enc.alz")
	payload := []byte("secret")
	pass := "pw123"
	data := buildAlzArchive(t, sampleFile{name: "secret.txt", data: payload, method: 0, encrypted: true, password: pass})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	arc, err := Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true, Password: pass, Concurrency: 1}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "secret.txt"))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("content mismatch")
	}

	err = arc.ExtractAll(ExtractOptions{Dest: filepath.Join(tmp, "wrong"), Quiet: true, Password: "nope", Concurrency: 1})
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected wrong password error, got %v", err)
	}
}

func TestExtractProvidedAlzTestdata(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{name: "encrypted.1234asdf!.alz", password: "1234asdf!"},
	}

	for _, tc := range cases {
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
			data, err := os.ReadFile(filepath.Join(dest, "data.txt"))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(data) != "unalz" {
				t.Fatalf("content = %q, want %q", data, "unalz")
			}
		})
	}
}

func TestExtractProvidedAlzFixtures(t *testing.T) {
	cases := []struct {
		name         string
		wantFileName string
		wantContent  string
		checkSize    bool
	}{
		{name: "nocompress.alz", wantFileName: "data.txt", wantContent: "unalz"},
		{name: "high.alz", wantFileName: "data.txt", wantContent: "unalz"},
		{name: "미즈노아미水野亜美マーキュリー🌈🌕🌊.alz", wantFileName: "미즈노아미水野?美マ?キュリ???????.txt", wantContent: "미즈노아미水野亜美マーキュリー🌈🌕🌊"},
		{name: "split.alz", wantFileName: "data.txt", checkSize: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			arc, err := Parse(testdataPath(tc.name))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(arc.Files) != 1 {
				t.Fatalf("files len = %d", len(arc.Files))
			}

			dest := t.TempDir()
			if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true}); err != nil {
				t.Fatalf("extract: %v", err)
			}

			data, err := os.ReadFile(filepath.Join(dest, tc.wantFileName))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if tc.checkSize {
				if int64(len(data)) != int64(arc.Files[0].Size) {
					t.Fatalf("size = %d, want %d", len(data), arc.Files[0].Size)
				}
				return
			}
			if string(data) != tc.wantContent {
				t.Fatalf("content = %q, want %q", data, tc.wantContent)
			}
		})
	}
}

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "alz", name)
}
