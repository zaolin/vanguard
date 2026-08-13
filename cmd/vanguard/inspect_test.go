package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	extcpio "github.com/cavaliergopher/cpio"
	cpionew "github.com/zaolin/vanguard/internal/cpio"
)

func TestFileType(t *testing.T) {
	tests := []struct {
		mode extcpio.FileMode
		want string
	}{
		{extcpio.TypeReg, "file"},
		{extcpio.TypeDir, "dir"},
		{extcpio.TypeSymlink, "symlink"},
		{extcpio.TypeChar, "char"},
		{extcpio.TypeBlock, "block"},
		{extcpio.TypeFifo, "fifo"},
		{0, "?"},
	}
	for _, tt := range tests {
		got := fileType(tt.mode)
		if got != tt.want {
			t.Errorf("fileType(%o) = %s, want %s", tt.mode, got, tt.want)
		}
	}
}

func TestPrintEntry(t *testing.T) {
	hdr := &extcpio.Header{
		Name: "test/file.txt",
		Mode: extcpio.TypeReg | 0644,
		Size: 1234,
	}
	// Just verify it doesn't panic
	printEntry(hdr, false)
	printEntry(hdr, true)
}

func TestParseUncompressedCPIO(t *testing.T) {
	// Build a real CPIO archive in a temp file
	var buf bytes.Buffer
	arch := cpionew.NewArchive(&buf)
	arch.AddFile("test.txt", []byte("hello"), 0644)
	arch.AddDirectory("dir", 0755)
	arch.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "initramfs.img")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	count, size, found, err := parseUncompressedCPIO(f, false)
	if err != nil {
		t.Fatalf("parseUncompressedCPIO: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if count != 2 { // test.txt + dir
		t.Errorf("count: got %d, want 2", count)
	}
	if size != 5 { // "hello" is 5 bytes, dir is 0
		t.Errorf("size: got %d, want 5", size)
	}
}

func TestParseUncompressedCPIOInvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not_extcpio.bin")
	if err := os.WriteFile(path, []byte("not a cpio archive"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	count, size, found, err := parseUncompressedCPIO(f, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false for non-CPIO data")
	}
	if count != 0 || size != 0 {
		t.Errorf("expected (0,0), got (%d,%d)", count, size)
	}
}

func TestParseCompressedCPIOGzip(t *testing.T) {
	// Build a CPIO, compress with gzip
	var cpioBuf bytes.Buffer
	arch := cpionew.NewArchive(&cpioBuf)
	arch.AddFile("compressed.txt", []byte("compressed content"), 0644)
	arch.Close()

	var gzipBuf bytes.Buffer
	gw := gzip.NewWriter(&gzipBuf)
	gw.Write(cpioBuf.Bytes())
	gw.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "initramfs.gz")
	if err := os.WriteFile(path, gzipBuf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	count, size, err := parseCompressedCPIO(f, false)
	if err != nil {
		t.Fatalf("parseCompressedCPIO: %v", err)
	}
	if count != 1 {
		t.Errorf("count: got %d, want 1", count)
	}
	if size != 18 { // "compressed content" = 17 bytes + trailing newline from cpio
		t.Errorf("size: got %d, want 18", size)
	}
}

func TestParseCompressedCPIOInvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.bin")
	if err := os.WriteFile(path, []byte{0x00, 0x00, 0x00, 0x00, 0x00}, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	_, _, err = parseCompressedCPIO(f, false)
	if err == nil {
		t.Error("expected error for unrecognized compression")
	}
}

func TestParseCompressedCPIOTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.bin")
	if err := os.WriteFile(path, []byte{0x01, 0x02}, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	_, _, err = parseCompressedCPIO(f, false)
	if err == nil {
		t.Error("expected error for too-small file")
	}
}

func TestInspectRunMissingFile(t *testing.T) {
	cmd := &InspectCmd{Path: "/nonexistent/initramfs.img"}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for missing file")
	}
}
