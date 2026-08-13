package firmware

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func TestDecompressGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("gzip test data"))
	gw.Close()

	result, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressGzip: %v", err)
	}
	if string(result) != "gzip test data" {
		t.Errorf("got %q, want %q", string(result), "gzip test data")
	}
}

func TestDecompressGzipInvalid(t *testing.T) {
	_, err := decompressGzip([]byte("not gzip"))
	if err == nil {
		t.Error("expected error for invalid gzip")
	}
}

func TestDecompressZstd(t *testing.T) {
	var buf bytes.Buffer
	enc, _ := zstd.NewWriter(&buf)
	enc.Write([]byte("zstd test data"))
	enc.Close()

	result, err := decompressZstd(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressZstd: %v", err)
	}
	if string(result) != "zstd test data" {
		t.Errorf("got %q, want %q", string(result), "zstd test data")
	}
}

func TestDecompressXZ(t *testing.T) {
	var buf bytes.Buffer
	xw, _ := xz.NewWriter(&buf)
	xw.Write([]byte("xz test data"))
	xw.Close()

	result, err := decompressXZ(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressXZ: %v", err)
	}
	if string(result) != "xz test data" {
		t.Errorf("got %q, want %q", string(result), "xz test data")
	}
}

func TestReadUncompressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firmware.bin")
	content := []byte("uncompressed firmware")
	os.WriteFile(path, content, 0644)

	f := File{SrcPath: path, DstPath: "/lib/firmware/firmware.bin", compressed: false}
	data, err := f.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("got %q, want %q", string(data), string(content))
	}
}

func TestReadCompressedGzip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firmware.bin.gz")
	content := []byte("compressed firmware")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(content)
	gw.Close()
	os.WriteFile(path, buf.Bytes(), 0644)

	f := File{SrcPath: path, DstPath: "/lib/firmware/firmware.bin", compressed: true}
	data, err := f.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("got %q, want %q", string(data), string(content))
	}
}

func TestReadMissingFile(t *testing.T) {
	f := File{SrcPath: "/nonexistent/file", compressed: false}
	_, err := f.Read()
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	// Create test firmware files
	relPath := "amd/sev.fw"
	fullPath := filepath.Join(dir, filepath.Dir(relPath))
	os.MkdirAll(fullPath, 0755)
	os.WriteFile(filepath.Join(dir, relPath), []byte("sev firmware"), 0644)

	// Also create a compressed variant
	gzPath := filepath.Join(dir, "amdgpu/vangogh.bin.gz")
	os.MkdirAll(filepath.Dir(gzPath), 0755)
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write([]byte("compressed amdgpu"))
	gw.Close()
	os.WriteFile(gzPath, gzBuf.Bytes(), 0644)

	// Override FirmwareBaseDir
	orig := FirmwareBaseDir
	FirmwareBaseDir = dir
	defer func() { FirmwareBaseDir = orig }()

	files, err := Collect([]string{relPath, "amdgpu/vangogh.bin"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	// First should be uncompressed
	if files[0].compressed {
		t.Error("first file should be uncompressed")
	}
	// Second should be compressed (found .gz variant)
	if !files[1].compressed {
		t.Error("second file should be compressed")
	}

	// Verify content can be read
	data, err := files[1].Read()
	if err != nil {
		t.Fatalf("Read compressed: %v", err)
	}
	if string(data) != "compressed amdgpu" {
		t.Errorf("decompressed: got %q, want %q", string(data), "compressed amdgpu")
	}
}

func TestCollectMissing(t *testing.T) {
	orig := FirmwareBaseDir
	FirmwareBaseDir = t.TempDir()
	defer func() { FirmwareBaseDir = orig }()

	_, err := Collect([]string{"nonexistent/firmware.bin"})
	if err == nil {
		t.Error("expected error for missing firmware")
	}
}

func TestCollectEmpty(t *testing.T) {
	orig := FirmwareBaseDir
	FirmwareBaseDir = t.TempDir()
	defer func() { FirmwareBaseDir = orig }()

	files, err := Collect([]string{})
	if err != nil {
		t.Fatalf("Collect empty: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}
