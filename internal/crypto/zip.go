package crypto

import (
	"fmt"

	"github.com/blurfx/unegg/internal/archive"
)

// ZipCrypto implements the traditional PKWARE ZipCrypto algorithm.
// This is the shared implementation used for both encryption and decryption.
type ZipCrypto struct {
	keys [3]uint32
}

// NewZipCrypto creates a new ZipCrypto instance initialized with the given password.
func NewZipCrypto(password string) *ZipCrypto {
	z := &ZipCrypto{}
	z.Reset(password)
	return z
}

// Reset reinitializes the cipher with the given password.
func (z *ZipCrypto) Reset(password string) {
	z.keys[0] = 0x12345678
	z.keys[1] = 0x23456789
	z.keys[2] = 0x34567890
	for i := 0; i < len(password); i++ {
		z.UpdateKeys(password[i])
	}
}

// UpdateKeys updates the internal key state with a plaintext byte.
func (z *ZipCrypto) UpdateKeys(b byte) {
	z.keys[0] = updateCRC32(z.keys[0], b)
	z.keys[1] = (z.keys[1]+(z.keys[0]&0xff))*0x8088405 + 1
	z.keys[2] = updateCRC32(z.keys[2], byte(z.keys[1]>>24))
}

// DecryptByte returns the next keystream byte for encryption/decryption.
func (z *ZipCrypto) DecryptByte() byte {
	tmp := z.keys[2] | 2
	return byte((tmp * (tmp ^ 1)) >> 8)
}

// ZipDecryptor implements traditional PKWARE ZipCrypto decryption.
type ZipDecryptor struct {
	*ZipCrypto
}

// NewZipDecryptor creates a new ZipCrypto decryptor.
// It validates the password against the 12-byte verification header.
func NewZipDecryptor(password string, verify []byte, crc uint32) (*ZipDecryptor, error) {
	z := &ZipDecryptor{ZipCrypto: NewZipCrypto(password)}

	if len(verify) != 12 {
		return nil, fmt.Errorf("zipcrypto: verify data length invalid")
	}

	tmp := make([]byte, len(verify))
	copy(tmp, verify)
	if err := z.Decrypt(tmp); err != nil {
		return nil, err
	}
	if tmp[11] != byte(crc>>24) {
		return nil, archive.ErrWrongPassword
	}
	return z, nil
}

// Decrypt decrypts the buffer in place.
func (z *ZipDecryptor) Decrypt(buf []byte) error {
	for i := 0; i < len(buf); i++ {
		b := buf[i] ^ z.DecryptByte()
		z.UpdateKeys(b)
		buf[i] = b
	}
	return nil
}

// Finish implements Decryptor. ZipCrypto has no final verification.
func (z *ZipDecryptor) Finish() error { return nil }

// ZipEncryptor implements ZipCrypto encryption for testing archive formats.
// This is used in test code to create encrypted test archives.
type ZipEncryptor struct {
	*ZipCrypto
}

// NewZipEncryptor creates a new ZipCrypto encryptor initialized with the given password.
func NewZipEncryptor(password string) *ZipEncryptor {
	return &ZipEncryptor{ZipCrypto: NewZipCrypto(password)}
}

// EncryptBytes encrypts plaintext bytes using ZipCrypto.
func (z *ZipEncryptor) EncryptBytes(plain []byte) []byte {
	out := make([]byte, len(plain))
	for i := range plain {
		ks := z.DecryptByte()
		out[i] = plain[i] ^ ks
		z.UpdateKeys(plain[i])
	}
	return out
}
