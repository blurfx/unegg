package archive

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SecureJoin safely joins base and rel paths, preventing path traversal attacks.
// It returns an error if the resulting path would escape the base directory.
func SecureJoin(base, rel string) (string, error) {
	// Check for Unix absolute paths
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: absolute path %q", ErrPathTraversal, rel)
	}

	// Check for Windows absolute paths (cross-platform detection)
	// Windows drive letter: C:, D:, etc.
	if len(rel) >= 2 && rel[1] == ':' &&
		((rel[0] >= 'A' && rel[0] <= 'Z') || (rel[0] >= 'a' && rel[0] <= 'z')) {
		return "", fmt.Errorf("%w: windows absolute path %q", ErrPathTraversal, rel)
	}
	// UNC paths: \\server or //server
	if strings.HasPrefix(rel, "\\\\") || strings.HasPrefix(rel, "//") {
		return "", fmt.Errorf("%w: UNC path %q", ErrPathTraversal, rel)
	}

	// On Unix, reject paths containing backslashes to prevent Windows-style
	// path traversal attempts (backslashes are valid filename chars on Unix)
	if filepath.Separator != '\\' && strings.ContainsRune(rel, '\\') {
		return "", fmt.Errorf("%w: backslash in path %q", ErrPathTraversal, rel)
	}

	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, rel)
	}

	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	joined := filepath.Join(baseAbs, rel)
	prefix := baseAbs
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}

	if joined != baseAbs && !strings.HasPrefix(joined, prefix) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, rel)
	}

	return joined, nil
}
