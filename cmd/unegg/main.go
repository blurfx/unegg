package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blurfx/unegg/internal/egg"
)

func main() {
	dest := flag.String("C", "", "destination directory (default: archive base name)")
	password := flag.String("p", "", "password for encrypted archives")
	list := flag.Bool("l", false, "list archive contents")
	concurrency := flag.Int("j", runtime.NumCPU(), "number of parallel workers")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <archive.egg>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	arc, err := egg.Parse(path)
	if err != nil {
		log.Fatalf("parse: %v", err)
	}

	if *list {
		printList(arc)
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
	}

	if err := arc.ExtractAll(opts); err != nil {
		log.Fatalf("extract: %v", err)
	}
}

func printList(arc *egg.Archive) {
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
