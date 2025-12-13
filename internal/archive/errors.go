package archive

import "errors"

// Common errors shared across archive formats.
var (
	// ErrBadSignature indicates the archive has an invalid or unrecognized signature.
	ErrBadSignature = errors.New("archive: invalid signature")

	// ErrUnsupportedMethod indicates an unsupported compression method.
	ErrUnsupportedMethod = errors.New("archive: unsupported compression method")

	// ErrWrongPassword indicates the provided password is incorrect.
	ErrWrongPassword = errors.New("archive: wrong password")

	// ErrUnsupportedEncryption indicates an unsupported encryption method.
	ErrUnsupportedEncryption = errors.New("archive: unsupported encryption method")

	// ErrAuthenticationFailed indicates MAC verification failed.
	ErrAuthenticationFailed = errors.New("archive: authentication failed")

	// ErrPathTraversal indicates an attempt to write outside the destination directory.
	ErrPathTraversal = errors.New("archive: path traversal detected")
)
