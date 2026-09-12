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

// TestAddDeviceNode_SerializesRdev is the regression test for the device
// node corruption: cavaliergopher/cpio v1.0.1 never writes the SVR4
// devmajor/devminor/rmajor/rminor fields (bytes 62-94 of the 110-byte
// header), so the kernel's initramfs parser created every node as (0,0).
// Verify the raw header bytes carry the major/minor after our patcher.
func TestAddDeviceNode_SerializesRdev(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.AddDeviceNode("dev/console", 0600, 'c', 5, 1); err != nil {
		t.Fatalf("AddDeviceNode: %v", err)
	}
	if err := a.AddDeviceNode("dev/null", 0666, 'c', 1, 3); err != nil {
		t.Fatalf("AddDeviceNode: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw := buf.Bytes()
	// Walk entries: find each header (070701 magic), extract the rdev fields.
	entries := 0
	for i := 0; i+svr4HeaderLen <= len(raw); {
		if !bytes.HasPrefix(raw[i:], []byte("070701")) {
			i++
			continue
		}
		nameSize := int(parseHexField(raw[i+94 : i+102]))
		name := string(raw[i+svr4HeaderLen : i+svr4HeaderLen+int(nameSize)-1])

		devMajor := parseHexField(raw[i+62 : i+70])
		devMinor := parseHexField(raw[i+70 : i+78])
		rMajor := parseHexField(raw[i+78 : i+86])
		rMinor := parseHexField(raw[i+86 : i+94])

		switch name {
		case "dev/console":
			entries++
			if devMajor != 5 || devMinor != 1 {
				t.Errorf("dev/console rdev: got (%d,%d), want (5,1)", devMajor, devMinor)
			}
			if rMajor != 5 || rMinor != 1 {
				t.Errorf("dev/console rmajor/rminor (kernel reads these): got (%d,%d), want (5,1)", rMajor, rMinor)
			}
		case "dev/null":
			entries++
			if devMajor != 1 || devMinor != 3 {
				t.Errorf("dev/null rdev: got (%d,%d), want (1,3)", devMajor, devMinor)
			}
			if rMajor != 1 || rMinor != 3 {
				t.Errorf("dev/null rmajor/rminor: got (%d,%d), want (1,3)", rMajor, rMinor)
			}
		}
		// Advance past header + name + padding to find the next header.
		i += svr4HeaderLen + int(nameSize)
	}
	if entries != 2 {
		t.Errorf("expected to verify 2 device-node headers, verified %d", entries)
	}
}

// parseHexField parses an 8-character uppercase-hex SVR4 header field.
func parseHexField(b []byte) int64 {
	var v int64
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int64(c - '0')
		case c >= 'A' && c <= 'F':
			v |= int64(c-'A') + 10
		default:
			return v
		}
	}
	return v
}

// TestAddDeviceNode_NoPatchWithoutDevice verifies the patcher stays armed
// only for the immediate next header (non-device entries keep rdev zero).
func TestAddDeviceNode_NoPatchWithoutDevice(t *testing.T) {
	var buf bytes.Buffer
	a := NewArchive(&buf)
	if err := a.AddFile("plain.txt", []byte("x"), 0644); err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if err := a.AddDeviceNode("dev/console", 0600, 'c', 5, 1); err != nil {
		t.Fatalf("AddDeviceNode: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw := buf.Bytes()
	found := 0
	for i := 0; i+svr4HeaderLen <= len(raw); {
		if !bytes.HasPrefix(raw[i:], []byte("070701")) {
			i++
			continue
		}
		nameSize := int(parseHexField(raw[i+94 : i+102]))
		name := string(raw[i+svr4HeaderLen : i+svr4HeaderLen+int(nameSize)-1])
		devMajor := parseHexField(raw[i+62 : i+70])
		devMinor := parseHexField(raw[i+70 : i+78])

		switch name {
		case "plain.txt":
			if devMajor != 0 || devMinor != 0 {
				t.Errorf("plain.txt rdev should be 0, got (%d,%d)", devMajor, devMinor)
			}
			found++
		case "dev/console":
			if devMajor != 5 || devMinor != 1 {
				t.Errorf("dev/console rdev: got (%d,%d), want (5,1)", devMajor, devMinor)
			}
			found++
		}
		i += svr4HeaderLen + int(nameSize)
	}
	if found != 2 {
		t.Errorf("expected 2 entries verified, got %d", found)
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
