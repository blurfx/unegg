package archive

import "runtime"

// ExtractOptions configures archive extraction behavior.
type ExtractOptions struct {
	// Dest is the destination directory for extracted files.
	Dest string

	// Password for encrypted archives. Empty string for unencrypted archives.
	Password string

	// Concurrency specifies the number of parallel extraction workers.
	// If <= 0, defaults to runtime.NumCPU().
	Concurrency int

	// Quiet suppresses progress output when true.
	Quiet bool
}

// WithDefaults returns a copy of opts with default values applied.
func (opts ExtractOptions) WithDefaults() ExtractOptions {
	if opts.Concurrency <= 0 {
		opts.Concurrency = runtime.NumCPU()
	}
	return opts
}
