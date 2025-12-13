package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blurfx/unegg/internal/alz"
	"github.com/blurfx/unegg/internal/egg"
)

func main() {
	dest := flag.String("C", "", "destination directory (default: archive base name)")
	password := flag.String("p", "", "password for encrypted archives")
	list := flag.Bool("l", false, "list archive contents")
	quiet := flag.Bool("q", false, "quiet mode (no progress output)")
	concurrency := flag.Int("j", runtime.NumCPU(), "number of parallel workers")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <archive.egg|archive.alz>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	arc, _, err := parseArchive(path)
	if err != nil {
		log.Fatalf("parse: %v", err)
	}

	if *list {
		switch a := arc.(type) {
		case *egg.Archive:
			printEggList(a)
		case *alz.Archive:
			printAlzList(a)
		default:
			log.Fatalf("parse: unsupported archive type")
		}
		return
	}

	destDir := *dest
	if destDir == "" {
		base := filepath.Base(path)
		ext := filepath.Ext(base)
		base = strings.TrimSuffix(base, ext)
		if base == "" {
			base = "egg-output"
		}
		destDir = base
	}

	opts := egg.ExtractOptions{
		Dest:        destDir,
		Password:    *password,
		Concurrency: *concurrency,
		Quiet:       *quiet,
	}

	switch a := arc.(type) {
	case *egg.Archive:
		err = a.ExtractAll(opts)
	case *alz.Archive:
		err = a.ExtractAll(opts)
	default:
		err = fmt.Errorf("unsupported archive type")
	}

	if err != nil {
		log.Fatalf("extract: %v", err)
	}
}

func printEggList(arc *egg.Archive) {
	for _, f := range arc.Files {
		name := f.Path
		if name == "" {
			name = fmt.Sprintf("%08d", f.Index)
		}
		mod := ""
		if !f.ModTime.IsZero() {
			mod = f.ModTime.In(time.Local).Format(time.RFC3339)
		}
		flags := ""
		if f.Attributes&egg.FileAttributeDirectory != 0 {
			flags += "d"
		}
		if f.Encryption != nil {
			flags += "e"
		}
		fmt.Printf("%12d  %-2s  %-20s  %s\n", f.Size, flags, mod, name)
	}
	if arc.Comment != "" {
		fmt.Printf("\nArchive comment: %s\n", arc.Comment)
	}
}

func printAlzList(arc *alz.Archive) {
	for _, f := range arc.Files {
		name := f.Name
		if name == "" {
			name = fmt.Sprintf("%08d", f.Index)
		}
		mod := ""
		if !f.ModTime.IsZero() {
			mod = f.ModTime.In(time.Local).Format(time.RFC3339)
		}
		flags := ""
		if f.Attributes&alz.FileAttributeDirectory != 0 {
			flags += "d"
		}
		if f.Encrypted {
			flags += "e"
		}
		fmt.Printf("%12d  %-2s  %-20s  %s\n", f.Size, flags, mod, name)
	}
	if arc.Comment != "" {
		fmt.Printf("\nArchive comment: %s\n", arc.Comment)
	}
}

func parseArchive(path string) (interface{}, string, error) {
	sig, sigErr := readSignature(path)
	if sigErr == nil {
		switch sig {
		case egg.SignatureHeader:
			arc, err := egg.Parse(path)
			return arc, "egg", err
		case alz.SignatureAlzHeader:
			arc, err := alz.Parse(path)
			return arc, "alz", err
		}
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".alz" {
		arc, err := alz.Parse(path)
		return arc, "alz", err
	}
	if ext == ".egg" {
		arc, err := egg.Parse(path)
		return arc, "egg", err
	}

	if arc, err := egg.Parse(path); err == nil {
		return arc, "egg", nil
	} else if !errors.Is(err, egg.ErrBadSignature) {
		return nil, "", err
	}
	arc, err := alz.Parse(path)
	if err != nil {
		return nil, "", err
	}
	return arc, "alz", nil
}

func readSignature(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var sig uint32
	if err := binary.Read(f, binary.LittleEndian, &sig); err != nil {
		return 0, err
	}
	return sig, nil
}
