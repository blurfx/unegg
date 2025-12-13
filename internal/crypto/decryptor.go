package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash/crc32"
	"io"
)

// Decryptor defines the interface for stream decryption.
type Decryptor interface {
	// Decrypt decrypts the buffer in place.
	Decrypt([]byte) error

	// Finish performs final verification (e.g., MAC check).
	Finish() error
}

// NopDecryptor is a no-op decryptor for unencrypted streams.
type NopDecryptor struct{}

// Decrypt implements Decryptor.
func (NopDecryptor) Decrypt([]byte) error { return nil }

// Finish implements Decryptor.
func (NopDecryptor) Finish() error { return nil }

// DecryptReader wraps a reader with decryption.
type DecryptReader struct {
	R   io.Reader
	Dec Decryptor
}

// Read implements io.Reader with decryption.
func (d *DecryptReader) Read(p []byte) (int, error) {
	n, err := d.R.Read(p)
	if n > 0 {
		if derr := d.Dec.Decrypt(p[:n]); derr != nil {
			return n, derr
		}
	}
	return n, err
}

// WriteCounter wraps a writer and counts bytes written.
type WriteCounter struct {
	W io.Writer
	N int64
}

// Write implements io.Writer with byte counting.
func (c *WriteCounter) Write(p []byte) (int, error) {
	n, err := c.W.Write(p)
	c.N += int64(n)
	return n, err
}

// updateCRC32 updates a CRC32 checksum with a single byte.
func updateCRC32(crc uint32, b byte) uint32 {
	return crc32.IEEETable[(byte(crc)^b)&0xff] ^ (crc >> 8)
}

// hmacSHA1 computes HMAC-SHA1 of data using the given key.
func hmacSHA1(key, data []byte) []byte {
	m := hmac.New(sha1.New, key)
	_, _ = m.Write(data)
	return m.Sum(nil)
}
