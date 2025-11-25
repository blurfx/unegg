package egg

import "errors"

var (
	ErrUnsupportedMethod   = errors.New("egg: unsupported compression method")
	ErrUnsupportedCrypto   = errors.New("egg: unsupported encryption method")
	ErrWrongPassword       = errors.New("egg: wrong password")
	ErrAuthenticationError = errors.New("egg: authentication failed")
)
