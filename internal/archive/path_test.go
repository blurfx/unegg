package archive

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureJoin(t *testing.T) {
	base := t.TempDir()

	tests := []struct {
		name    string
		rel     string
		wantErr bool
	}{
		{
			name:    "simple file",
			rel:     "file.txt",
			wantErr: false,
		},
		{
			name:    "nested path",
			rel:     "foo/bar/baz.txt",
			wantErr: false,
		},
		{
			name:    "dot segments cleaned",
			rel:     "foo/./bar/../baz.txt",
			wantErr: false,
		},
		{
			name:    "absolute path rejected",
			rel:     "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "parent traversal rejected",
			rel:     "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "parent only rejected",
			rel:     "..",
			wantErr: true,
		},
		{
			name:    "parent prefix rejected",
			rel:     "../sibling/file.txt",
			wantErr: true,
		},
		{
			name:    "windows absolute path rejected",
			rel:     "C:\\Windows\\System32",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SecureJoin(base, tt.rel)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SecureJoin(%q, %q) expected error, got nil", base, tt.rel)
				}
				return
			}

			if err != nil {
				t.Errorf("SecureJoin(%q, %q) unexpected error: %v", base, tt.rel, err)
				return
			}

			// Verify result is within base
			if !strings.HasPrefix(result, base) {
				t.Errorf("SecureJoin(%q, %q) = %q, not within base", base, tt.rel, result)
			}

			// Verify it's an absolute path
			if !filepath.IsAbs(result) {
				t.Errorf("SecureJoin(%q, %q) = %q, not absolute", base, tt.rel, result)
			}
		})
	}
}

func TestSecureJoinNoTraversal(t *testing.T) {
	base := "/safe/directory"
	malicious := []string{
		"../../../etc/passwd",
		"foo/../../../../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
	}

	for _, path := range malicious {
		result, err := SecureJoin(base, path)
		if err == nil {
			t.Errorf("SecureJoin should reject path traversal %q, got result: %q", path, result)
		}
	}
}
