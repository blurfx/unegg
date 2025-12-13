package archive

import (
	"runtime"
	"testing"
)

func TestExtractOptionsWithDefaults(t *testing.T) {
	tests := []struct {
		name           string
		opts           ExtractOptions
		wantConcurrent int
	}{
		{
			name:           "zero concurrency uses NumCPU",
			opts:           ExtractOptions{Concurrency: 0},
			wantConcurrent: runtime.NumCPU(),
		},
		{
			name:           "negative concurrency uses NumCPU",
			opts:           ExtractOptions{Concurrency: -1},
			wantConcurrent: runtime.NumCPU(),
		},
		{
			name:           "positive concurrency preserved",
			opts:           ExtractOptions{Concurrency: 4},
			wantConcurrent: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.opts.WithDefaults()
			if result.Concurrency != tt.wantConcurrent {
				t.Errorf("WithDefaults().Concurrency = %d, want %d",
					result.Concurrency, tt.wantConcurrent)
			}
		})
	}
}

func TestExtractOptionsPreservesOtherFields(t *testing.T) {
	opts := ExtractOptions{
		Dest:        "/output",
		Password:    "secret",
		Concurrency: 0,
		Quiet:       true,
	}

	result := opts.WithDefaults()

	if result.Dest != opts.Dest {
		t.Errorf("WithDefaults() changed Dest to %q", result.Dest)
	}
	if result.Password != opts.Password {
		t.Errorf("WithDefaults() changed Password")
	}
	if result.Quiet != opts.Quiet {
		t.Errorf("WithDefaults() changed Quiet to %v", result.Quiet)
	}
}
