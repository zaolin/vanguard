package luks

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// createTestLUKS2Image creates a temporary file with a valid LUKS2 header
// (magic + version + hdr_len + JSON area) and returns its path.
// The JSON area is filled with padding bytes of the given content.
func createTestLUKS2Image(t *testing.T, jsonContent string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test-luks.img")

	// Build a minimal LUKS2 header
	// Binary header: 6 bytes magic + 2 bytes version + 8 bytes hdr_len + padding to 0x1000
	jsonArea := []byte(jsonContent)
	hdrLen := uint64(0x1000 + len(jsonArea))

	binHeader := make([]byte, 0x1000)
	copy(binHeader[0:4], []byte("LUKS"))
	binHeader[4] = 0xba
	binHeader[5] = 0xbe
	binary.BigEndian.PutUint16(binHeader[6:8], 2) // version 2
	binary.BigEndian.PutUint64(binHeader[8:16], hdrLen)

	// Write the file
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(binHeader); err != nil {
		t.Fatalf("Write binHeader: %v", err)
	}
	if _, err := f.Write(jsonArea); err != nil {
		t.Fatalf("Write jsonArea: %v", err)
	}

	return path
}

func TestHashLUKS2Header_BasicHash(t *testing.T) {
	path := createTestLUKS2Image(t, `{"keyslots":{},"tokens":{}}`)

	digest, err := HashLUKS2Header(path)
	if err != nil {
		t.Fatalf("HashLUKS2Header: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("digest length: got %d, want 32", len(digest))
	}
}

func TestHashLUKS2Header_Deterministic(t *testing.T) {
	jsonContent := `{"keyslots":{"0":{}},"tokens":{"0":{}}}`
	path1 := createTestLUKS2Image(t, jsonContent)
	path2 := createTestLUKS2Image(t, jsonContent)

	d1, err := HashLUKS2Header(path1)
	if err != nil {
		t.Fatalf("HashLUKS2Header 1: %v", err)
	}
	d2, err := HashLUKS2Header(path2)
	if err != nil {
		t.Fatalf("HashLUKS2Header 2: %v", err)
	}

	if !digestsEqual(d1, d2) {
		t.Errorf("Same header content should produce same hash:\n  d1: %x\n  d2: %x", d1, d2)
	}
}

func TestHashLUKS2Header_DifferentContentDifferentHash(t *testing.T) {
	path1 := createTestLUKS2Image(t, `{"keyslots":{"0":{}}}`)
	path2 := createTestLUKS2Image(t, `{"keyslots":{"0":{},"1":{}}}`)

	d1, err := HashLUKS2Header(path1)
	if err != nil {
		t.Fatalf("HashLUKS2Header 1: %v", err)
	}
	d2, err := HashLUKS2Header(path2)
	if err != nil {
		t.Fatalf("HashLUKS2Header 2: %v", err)
	}

	if digestsEqual(d1, d2) {
		t.Error("Different header content should produce different hashes")
	}
}

func TestHashLUKS2Header_TamperDetection(t *testing.T) {
	// Simulate adding a keyslot: the JSON area changes, so the hash should change
	path := createTestLUKS2Image(t, `{"keyslots":{"0":{}}}`)

	originalHash, err := HashLUKS2Header(path)
	if err != nil {
		t.Fatalf("HashLUKS2Header original: %v", err)
	}

	// Modify the file: append a keyslot to the JSON area
	// Read the full file, modify the JSON, rewrite with updated hdr_len
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Replace JSON area with a different one
	newJSON := []byte(`{"keyslots":{"0":{},"1":{}}}`)
	newHdrLen := uint64(0x1000 + len(newJSON))
	binary.BigEndian.PutUint64(data[8:16], newHdrLen)
	data = append(data[:0x1000], newJSON...)

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tamperedHash, err := HashLUKS2Header(path)
	if err != nil {
		t.Fatalf("HashLUKS2Header tampered: %v", err)
	}

	if digestsEqual(originalHash, tamperedHash) {
		t.Error("Tampered header (added keyslot) should produce different hash")
	}
}

func TestHashLUKS2Header_NotLUKSShouldFail(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "not-luks.img")
	if err := os.WriteFile(path, []byte("not a LUKS header"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := HashLUKS2Header(path)
	if err == nil {
		t.Error("HashLUKS2Header should fail for non-LUKS file")
	}
}

func TestHashLUKS2Header_LUKS1ShouldFail(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "luks1.img")
	// LUKS1 header: magic + version 1
	header := make([]byte, 0x1000)
	copy(header[0:4], []byte("LUKS"))
	header[4] = 0xba
	header[5] = 0xbe
	binary.BigEndian.PutUint16(header[6:8], 1) // version 1

	if err := os.WriteFile(path, header, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := HashLUKS2Header(path)
	if err == nil {
		t.Error("HashLUKS2Header should fail for LUKS1")
	}
}

func TestHashLUKS2Header_MatchesDirectSHA256(t *testing.T) {
	jsonContent := `{"keyslots":{}}`
	path := createTestLUKS2Image(t, jsonContent)

	digest, err := HashLUKS2Header(path)
	if err != nil {
		t.Fatalf("HashLUKS2Header: %v", err)
	}

	// Compute expected hash manually
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	hdrLen := binary.BigEndian.Uint64(data[8:16])
	expected := sha256.Sum256(data[:hdrLen])

	if !digestsEqual(digest, expected[:]) {
		t.Errorf("Hash mismatch:\n  got:  %x\n  want: %x", digest, expected[:])
	}
}

func TestHashLUKS2Header_ReadOnly(t *testing.T) {
	// Verify that HashLUKS2Header does not modify the device file
	path := createTestLUKS2Image(t, `{"keyslots":{}}`)

	// Read original content
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Hash the header
	if _, err := HashLUKS2Header(path); err != nil {
		t.Fatalf("HashLUKS2Header: %v", err)
	}

	// Read again and compare
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after: %v", err)
	}

	if len(original) != len(after) {
		t.Errorf("File size changed: %d -> %d", len(original), len(after))
	}
	for i := range original {
		if original[i] != after[i] {
			t.Errorf("File content changed at byte %d: 0x%02x -> 0x%02x", i, original[i], after[i])
			break
		}
	}
}

func TestHashLUKS2Header_NonexistentDevice(t *testing.T) {
	_, err := HashLUKS2Header("/dev/nonexistent-device-12345")
	if err == nil {
		t.Error("HashLUKS2Header should fail for nonexistent device")
	}
}

func TestHashLUKS2Header_InvalidHeaderLength(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-luks.img")

	// Create a LUKS2 header with an invalid hdr_len (too small)
	header := make([]byte, 32)
	copy(header[0:4], []byte("LUKS"))
	header[4] = 0xba
	header[5] = 0xbe
	binary.BigEndian.PutUint16(header[6:8], 2)
	binary.BigEndian.PutUint64(header[8:16], 0x100) // too small, < 0x1000

	if err := os.WriteFile(path, header, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := HashLUKS2Header(path)
	if err == nil {
		t.Error("HashLUKS2Header should fail for invalid header length")
	}
}

func digestsEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
