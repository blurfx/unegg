package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/blurfx/unegg/internal/archive"
)

// AESDecryptor implements AES-CTR decryption for EGG archives.
type AESDecryptor struct {
	block       cipher.Block
	nonce       [aes.BlockSize]byte
	keystream   [aes.BlockSize]byte
	ksPos       int
	mac         hash.Hash
	expectedMAC []byte
}

// NewAESDecryptor creates a new AES decryptor for the given encryption method.
// method 1 = AES-128, method 2 = AES-256.
func NewAESDecryptor(method byte, password string, saltHeader, mac []byte) (*AESDecryptor, error) {
	_, keyLen, saltLen, macLen := aesParams(method)
	if keyLen == 0 {
		return nil, archive.ErrUnsupportedEncryption
	}
	if len(saltHeader) != saltLen+2 {
		return nil, fmt.Errorf("aes: unexpected header length %d", len(saltHeader))
	}
	if macLen > 0 && len(mac) != macLen {
		return nil, fmt.Errorf("aes: unexpected mac length %d", len(mac))
	}

	derived := pbkdf2SHA1([]byte(password), saltHeader[:saltLen], 1000, 2*keyLen+2)
	pwdVerify := derived[2*keyLen : 2*keyLen+2]
	if !hmac.Equal(pwdVerify, saltHeader[saltLen:]) {
		return nil, archive.ErrWrongPassword
	}

	block, err := aes.NewCipher(derived[:keyLen])
	if err != nil {
		return nil, err
	}
	macKey := derived[keyLen : 2*keyLen]
	h := hmac.New(sha1.New, macKey)

	d := &AESDecryptor{
		block:       block,
		ksPos:       aes.BlockSize,
		mac:         h,
		expectedMAC: mac,
	}
	return d, nil
}

// aesParams returns parameters for the given AES method.
func aesParams(method byte) (mode int, keyLen, saltLen, macLen int) {
	switch method {
	case 1: // AES-128
		return 1, 16, 8, 10
	case 2: // AES-256
		return 3, 32, 16, 10
	default:
		return 0, 0, 0, 0
	}
}

func (a *AESDecryptor) xorKeyStream(buf []byte) {
	for i := range buf {
		if a.ksPos == len(a.keystream) {
			// Increment nonce (little-endian on first 8 bytes) then encrypt.
			for j := 0; j < 8; j++ {
				a.nonce[j]++
				if a.nonce[j] != 0 {
					break
				}
			}
			a.block.Encrypt(a.keystream[:], a.nonce[:])
			a.ksPos = 0
		}
		buf[i] ^= a.keystream[a.ksPos]
		a.ksPos++
	}
}

// Decrypt decrypts the buffer in place.
func (a *AESDecryptor) Decrypt(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	// HMAC is computed over ciphertext.
	_, _ = a.mac.Write(buf)
	a.xorKeyStream(buf)
	return nil
}

// Finish verifies the MAC after all data has been decrypted.
func (a *AESDecryptor) Finish() error {
	if len(a.expectedMAC) == 0 {
		return nil
	}
	sum := a.mac.Sum(nil)
	if !hmac.Equal(a.expectedMAC, sum[:len(a.expectedMAC)]) {
		return archive.ErrAuthenticationFailed
	}
	return nil
}

// pbkdf2SHA1 derives a key using PBKDF2-HMAC-SHA1.
func pbkdf2SHA1(password, salt []byte, iter, outLen int) []byte {
	h := sha1.New
	hashLen := h().Size()
	numBlocks := (outLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)

	for i := 1; i <= numBlocks; i++ {
		binary.BigEndian.PutUint32(buf[len(salt):], uint32(i))
		u := hmacSHA1(password, buf)
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iter; j++ {
			u = hmacSHA1(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:outLen]
}
