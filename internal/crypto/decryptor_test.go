package crypto

import (
	"bytes"
	"io"
	"testing"
)

func TestWriteCounter(t *testing.T) {
	var buf bytes.Buffer
	counter := &WriteCounter{W: &buf}

	data1 := []byte("hello")
	n, err := counter.Write(data1)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data1) {
		t.Errorf("Write returned %d, want %d", n, len(data1))
	}
	if counter.N != int64(len(data1)) {
		t.Errorf("Counter.N = %d, want %d", counter.N, len(data1))
	}

	data2 := []byte(" world")
	n, err = counter.Write(data2)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if counter.N != int64(len(data1)+len(data2)) {
		t.Errorf("Counter.N = %d, want %d", counter.N, len(data1)+len(data2))
	}

	if buf.String() != "hello world" {
		t.Errorf("Buffer contains %q, want %q", buf.String(), "hello world")
	}
}

func TestDecryptReader(t *testing.T) {
	// Test with NopDecryptor
	input := []byte("test data")
	r := bytes.NewReader(input)
	dec := &DecryptReader{
		R:   r,
		Dec: NopDecryptor{},
	}

	output, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(output, input) {
		t.Errorf("DecryptReader output = %q, want %q", output, input)
	}
}

func TestNopDecryptor(t *testing.T) {
	dec := NopDecryptor{}

	data := []byte("test")
	if err := dec.Decrypt(data); err != nil {
		t.Errorf("NopDecryptor.Decrypt returned error: %v", err)
	}

	if err := dec.Finish(); err != nil {
		t.Errorf("NopDecryptor.Finish returned error: %v", err)
	}

	// Verify data unchanged
	if string(data) != "test" {
		t.Errorf("NopDecryptor modified data to %q", data)
	}
}
