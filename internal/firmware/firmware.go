package firmware

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const FirmwareBaseDir = "/lib/firmware"

// Supported compression extensions in order of preference
var compressionExts = []string{"", ".zst", ".xz", ".gz"}

// File represents a firmware file to include in the initramfs
type File struct {
	SrcPath    string // Absolute path on host (may be compressed)
	DstPath    string // Path in initramfs (always uncompressed name)
	compressed bool   // Whether the source file is compressed
}

// Collect gathers specific firmware files from the provided list
// Each entry should be a path relative to /lib/firmware/
// If the uncompressed file doesn't exist, it will look for compressed variants
func Collect(files []string) ([]File, error) {
	var result []File

	for _, relPath := range files {
		found := false

		// Try uncompressed first, then compressed variants
		for _, ext := range compressionExts {
			srcPath := filepath.Join(FirmwareBaseDir, relPath+ext)

			info, err := os.Stat(srcPath)
			if err != nil {
				continue // Try next extension
			}
			if info.IsDir() {
				continue // Skip directories
			}

			result = append(result, File{
				SrcPath:    srcPath,
				DstPath:    filepath.Join("/lib/firmware", relPath), // Always uncompressed name
				compressed: ext != "",
			})
			found = true
			break
		}

		if !found {
			return nil, fmt.Errorf("firmware file not found: %s (tried %s and compressed variants)",
				relPath, filepath.Join(FirmwareBaseDir, relPath))
		}
	}

	return result, nil
}

// Read reads the content of a firmware file, decompressing if necessary
func (f *File) Read() ([]byte, error) {
	data, err := os.ReadFile(f.SrcPath)
	if err != nil {
		return nil, err
	}

	if !f.compressed {
		return data, nil
	}

	// Decompress based on file extension
	switch {
	case strings.HasSuffix(f.SrcPath, ".zst"):
		return decompressZstd(data)
	case strings.HasSuffix(f.SrcPath, ".xz"):
		return decompressXZ(data)
	case strings.HasSuffix(f.SrcPath, ".gz"):
		return decompressGzip(data)
	default:
		return data, nil
	}
}

// decompressZstd decompresses zstd-compressed data
func decompressZstd(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zstd decoder error: %w", err)
	}
	defer decoder.Close()

	return io.ReadAll(decoder)
}

// decompressXZ decompresses xz-compressed data
func decompressXZ(data []byte) ([]byte, error) {
	reader, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("xz decoder error: %w", err)
	}

	return io.ReadAll(reader)
}

// decompressGzip decompresses gzip-compressed data
func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip decoder error: %w", err)
	}
	defer reader.Close()

	return io.ReadAll(reader)
}
