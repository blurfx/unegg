package egg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
)

type decryptor interface {
	Decrypt([]byte) error
	Finish() error
}

type nopDecryptor struct{}

func (nopDecryptor) Decrypt([]byte) error { return nil }
func (nopDecryptor) Finish() error        { return nil }

type zipDecryptor struct {
	keys [3]uint32
}

func newZipDecryptor(password string, verify []byte, crc uint32) (*zipDecryptor, error) {
	z := &zipDecryptor{}
	z.reset(password)

	if len(verify) != 12 {
		return nil, fmt.Errorf("zipcrypto: verify data length invalid")
	}
	tmp := make([]byte, len(verify))
	copy(tmp, verify)
	if err := z.Decrypt(tmp); err != nil {
		return nil, err
	}
	if tmp[11] != byte(crc>>24) {
		return nil, ErrWrongPassword
	}
	return z, nil
}

func (z *zipDecryptor) reset(password string) {
	z.keys[0] = 0x12345678
	z.keys[1] = 0x23456789
	z.keys[2] = 0x34567890
	for i := 0; i < len(password); i++ {
		z.updateKeys(password[i])
	}
}

func (z *zipDecryptor) updateKeys(b byte) {
	z.keys[0] = crc32.Update(z.keys[0], crc32.IEEETable, []byte{b})
	z.keys[1] = (z.keys[1]+(z.keys[0]&0xff))*0x8088405 + 1
	z.keys[2] = crc32.Update(z.keys[2], crc32.IEEETable, []byte{byte(z.keys[1] >> 24)})
}

func (z *zipDecryptor) decryptByte() byte {
	tmp := z.keys[2] | 2
	return byte((tmp * (tmp ^ 1)) >> 8)
}

func (z *zipDecryptor) Decrypt(buf []byte) error {
	for i := 0; i < len(buf); i++ {
		b := buf[i] ^ z.decryptByte()
		z.updateKeys(b)
		buf[i] = b
	}
	return nil
}

func (z *zipDecryptor) Finish() error { return nil }

// AES-CTR + HMAC-SHA1 (Gladman fileenc)

type aesDecryptor struct {
	block       cipher.Block
	nonce       [aes.BlockSize]byte
	keystream   [aes.BlockSize]byte
	ksPos       int
	mac         hash.Hash
	expectedMac []byte
}

func newAESDecryptor(method byte, password string, saltHeader, mac []byte) (*aesDecryptor, error) {
	mode, keyLen, saltLen, macLen := aesParams(method)
	if mode == 0 {
		return nil, ErrUnsupportedCrypto
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
		return nil, ErrWrongPassword
	}

	block, err := aes.NewCipher(derived[:keyLen])
	if err != nil {
		return nil, err
	}
	macKey := derived[keyLen : 2*keyLen]
	h := hmac.New(sha1.New, macKey)

	d := &aesDecryptor{
		block:       block,
		ksPos:       aes.BlockSize,
		mac:         h,
		expectedMac: mac,
	}
	return d, nil
}

func aesParams(method byte) (mode int, keyLen, saltLen, macLen int) {
	switch method {
	case 1: // AES128
		return 1, 16, 8, 10
	case 2: // AES256 (mode 3 in reference)
		return 3, 32, 16, 10
	default:
		return 0, 0, 0, 0
	}
}

func (a *aesDecryptor) xorKeyStream(buf []byte) {
	for i := range buf {
		if a.ksPos == len(a.keystream) {
			// increment nonce little-endian on first 8 bytes then encrypt.
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

func (a *aesDecryptor) Decrypt(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	// HMAC is computed over ciphertext.
	_, _ = a.mac.Write(buf)
	a.xorKeyStream(buf)
	return nil
}

func (a *aesDecryptor) Finish() error {
	if len(a.expectedMac) == 0 {
		return nil
	}
	sum := a.mac.Sum(nil)
	if !hmac.Equal(a.expectedMac, sum[:len(a.expectedMac)]) {
		return ErrAuthenticationError
	}
	return nil
}

func pbkdf2SHA1(password, salt []byte, iter, outLen int) []byte {
	// small PBKDF2 implementation to avoid pulling an extra dependency.
	h := sha1.New
	hashLen := h().Size()
	numBlocks := (outLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)

	for i := 1; i <= numBlocks; i++ {
		binary.BigEndian.PutUint32(buf[len(salt):], uint32(i))
		u := hmacSha1(password, buf)
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iter; j++ {
			u = hmacSha1(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:outLen]
}

func hmacSha1(key, data []byte) []byte {
	m := hmac.New(sha1.New, key)
	_, _ = m.Write(data)
	return m.Sum(nil)
}
