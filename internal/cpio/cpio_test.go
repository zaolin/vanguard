package cpio

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavaliergopher/cpio"
)

func TestAddFile(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	content := []byte("test file content")
	if err := a.AddFile("test.txt", content, 0644); err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reader := cpio.NewReader(&buf)
	hdr, err := reader.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if hdr.Name != "test.txt" {
		t.Errorf("Name: got %s, want test.txt", hdr.Name)
	}
	if hdr.Size != int64(len(content)) {
		t.Errorf("Size: got %d, want %d", hdr.Size, len(content))
	}
	if hdr.Mode&cpio.TypeReg == 0 {
		t.Errorf("Mode: expected regular file, got %v", hdr.Mode)
	}
}

func TestAddDirectory(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.AddDirectory("test/dir", 0755); err != nil {
		t.Fatalf("AddDirectory: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reader := cpio.NewReader(&buf)
	hdr, err := reader.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if hdr.Name != "test/dir" {
		t.Errorf("Name: got %s, want test/dir", hdr.Name)
	}
	if hdr.Mode&cpio.TypeDir == 0 {
		t.Errorf("Mode: expected directory, got %v", hdr.Mode)
	}
}

func TestAddSymlink(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.AddSymlink("link", "/target/path"); err != nil {
		t.Fatalf("AddSymlink: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reader := cpio.NewReader(&buf)
	hdr, err := reader.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if hdr.Name != "link" {
		t.Errorf("Name: got %s, want link", hdr.Name)
	}
	if hdr.Linkname != "/target/path" {
		t.Errorf("Linkname: got %s, want /target/path", hdr.Linkname)
	}
	if hdr.Mode&cpio.TypeSymlink == 0 {
		t.Errorf("Mode: expected symlink, got %v", hdr.Mode)
	}
}

func TestAddDeviceNode(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.AddDeviceNode("/dev/test", 0600, 'c', 10, 224); err != nil {
		t.Fatalf("AddDeviceNode char: %v", err)
	}
	if err := a.AddDeviceNode("/dev/block", 0660, 'b', 254, 0); err != nil {
		t.Fatalf("AddDeviceNode block: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reader := cpio.NewReader(&buf)
	// Check char device
	hdr, err := reader.Next()
	if err != nil {
		t.Fatalf("Next (char): %v", err)
	}
	if hdr.Mode&cpio.TypeChar == 0 {
		t.Errorf("Mode: expected char device, got %v", hdr.Mode)
	}
	if hdr.Name != "/dev/test" {
		t.Errorf("Name: got %s, want /dev/test", hdr.Name)
	}

	// Check block device
	hdr, err = reader.Next()
	if err != nil {
		t.Fatalf("Next (block): %v", err)
	}
	if hdr.Mode&cpio.TypeBlock == 0 {
		t.Errorf("Mode: expected block device, got %v", hdr.Mode)
	}
	if hdr.Name != "/dev/block" {
		t.Errorf("Name: got %s, want /dev/block", hdr.Name)
	}
}

func TestAddFileFromDisk(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "source.txt")
	content := []byte("from disk")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.AddFileFromDisk(srcPath, "dest.txt"); err != nil {
		t.Fatalf("AddFileFromDisk: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reader := cpio.NewReader(&buf)
	hdr, err := reader.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if hdr.Name != "dest.txt" {
		t.Errorf("Name: got %s, want dest.txt", hdr.Name)
	}
	if hdr.Size != int64(len(content)) {
		t.Errorf("Size: got %d, want %d", hdr.Size, len(content))
	}
}

func TestAddFileFromDiskMissing(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	err := a.AddFileFromDisk("/nonexistent/file", "dest.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestClose(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Closing twice should produce an error or no-op
	// (cpio.Writer.Close writes the trailer, second call may error)
	_ = a.Close()
}
