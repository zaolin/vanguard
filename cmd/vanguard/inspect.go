package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"

	"github.com/cavaliergopher/cpio"
	"github.com/klauspost/compress/zstd"
)

// InspectCmd lists the contents of a generated initramfs without extracting.
// It reads the CPIO archive(s) — vanguard generates a chained archive with
// an optional uncompressed early firmware CPIO followed by a compressed main
// CPIO (zstd or gzip).
type InspectCmd struct {
	Path    string `short:"p" required:"" help:"Path to initramfs image"`
	Verbose bool   `short:"v" help:"Show file sizes and permissions"`
}

// maxInspectEntries prevents OOM/DoS from a crafted archive with millions of
// entries.
const maxInspectEntries = 100000

func (c *InspectCmd) Run() error {
	if _, err := os.Stat(c.Path); err != nil {
		return fmt.Errorf("initramfs not found: %s", c.Path)
	}

	f, err := os.Open(c.Path)
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer f.Close()

	fmt.Println()
	fmt.Println("  " + headerSty.Render("INITRAMFS CONTENTS"))
	fmt.Println()

	fileCount := 0
	totalSize := int64(0)

	// Phase 1: Try to parse as uncompressed CPIO (early firmware segment).
	// The kernel unpacks CPIO archives in sequence; the early firmware CPIO
	// is uncompressed, followed by a compressed main CPIO. We try the
	// uncompressed CPIO first; when it ends (TRAILER!!!), we check if there's
	// a compressed segment following.
	earlyCount, earlySize, hasEarly, err := parseUncompressedCPIO(f, c.Verbose)
	if hasEarly {
		fileCount += earlyCount
		totalSize += earlySize

		// After the early uncompressed CPIO, try to read the compressed segment
		if _, err := f.Seek(0, 1); err == nil {
			// Check if there's more data (compressed segment)
			if stat, _ := f.Stat(); stat != nil {
				if pos, _ := f.Seek(0, 1); pos < stat.Size() {
					fmt.Println()
					fmt.Println("  " + headerSty.Render("MAIN ARCHIVE (compressed)"))
					fmt.Println()

					mainCount, mainSize, err := parseCompressedCPIO(f, c.Verbose)
					if err != nil {
						fmt.Printf("  warning: compressed segment parse error: %v\n", err)
					}
					fileCount += mainCount
					totalSize += mainSize
				}
			}
		}
	} else {
		// Phase 2: Not an uncompressed CPIO — try compressed directly
		f.Seek(0, 0)
		mainCount, mainSize, err := parseCompressedCPIO(f, c.Verbose)
		if err != nil {
			return fmt.Errorf("failed to parse initramfs: %w", err)
		}
		fileCount += mainCount
		totalSize += mainSize
	}

	fmt.Println()
	fmt.Printf("  Total: %d files, %d bytes\n", fileCount, totalSize)
	fmt.Println()

	return nil
}

// parseUncompressedCPIO tries to read an uncompressed CPIO from the current
// position. Returns the count, total size, whether it found a valid CPIO,
// and any error. If the data doesn't start with "070701", returns (0,0,false,nil).
func parseUncompressedCPIO(f *os.File, verbose bool) (count int, size int64, found bool, err error) {
	// Peek at the first 6 bytes to check for CPIO magic
	magic := make([]byte, 6)
	n, _ := f.Read(magic)
	if n < 6 || string(magic) != "070701" {
		return 0, 0, false, nil
	}
	// Seek back so the cpio.Reader can read from the start
	f.Seek(0, 0)

	cReader := cpio.NewReader(f)
	for {
		hdr, err := cReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return count, size, true, err
		}

		if hdr.Name == "TRAILER!!!" {
			break
		}
		if hdr.Name == "." {
			continue
		}

		count++
		if count > maxInspectEntries {
			return count, size, true, fmt.Errorf("too many entries (>%d) — possible crafted archive", maxInspectEntries)
		}
		size += hdr.Size

		printEntry(hdr, verbose)
	}

	return count, size, true, nil
}

// parseCompressedCPIO reads a compressed CPIO from the current file position.
// It detects zstd or gzip magic and wraps the file in a decompressor before
// passing to cpio.Reader.
func parseCompressedCPIO(f *os.File, verbose bool) (count int, size int64, err error) {
	// Read the first 4 bytes to detect compression
	header := make([]byte, 4)
	n, _ := f.Read(header)
	if n < 4 {
		return 0, 0, fmt.Errorf("compressed segment too small")
	}
	f.Seek(-int64(n), 1) // seek back to before the header we just read

	var decompressor io.Reader

	if header[0] == 0x28 && header[1] == 0xB5 && header[2] == 0x2F && header[3] == 0xFD {
		// zstd magic
		zr, err := zstd.NewReader(f)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to open zstd: %w", err)
		}
		defer zr.Close()
		decompressor = zr
	} else if header[0] == 0x1F && header[1] == 0x8B {
		// gzip magic
		gr, err := gzip.NewReader(f)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to open gzip: %w", err)
		}
		defer gr.Close()
		decompressor = gr
	} else {
		return 0, 0, fmt.Errorf("unrecognized compression format (expected zstd or gzip magic)")
	}

	cReader := cpio.NewReader(decompressor)
	for {
		hdr, err := cReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return count, size, err
		}

		if hdr.Name == "TRAILER!!!" {
			break
		}
		if hdr.Name == "." {
			continue
		}

		count++
		if count > maxInspectEntries {
			return count, size, fmt.Errorf("too many entries (>%d) — possible crafted archive", maxInspectEntries)
		}
		size += hdr.Size

		printEntry(hdr, verbose)
	}

	return count, size, nil
}

// printEntry prints a single CPIO entry in the requested format.
func printEntry(hdr *cpio.Header, verbose bool) {
	if verbose {
		mode := fmt.Sprintf("%#o", hdr.Mode.Perm())
		typ := fileType(hdr.Mode)
		fmt.Printf("  %-60s %10d bytes  %s  %s\n", hdr.Name, hdr.Size, mode, typ)
	} else {
		fmt.Printf("  %s\n", hdr.Name)
	}
}

// fileType returns a human-readable file type string from the CPIO mode.
func fileType(mode cpio.FileMode) string {
	switch {
	case mode&cpio.TypeReg != 0:
		return "file"
	case mode&cpio.TypeDir != 0:
		return "dir"
	case mode&cpio.TypeSymlink != 0:
		return "symlink"
	case mode&cpio.TypeChar != 0:
		return "char"
	case mode&cpio.TypeBlock != 0:
		return "block"
	case mode&cpio.TypeFifo != 0:
		return "fifo"
	default:
		return "?"
	}
}
