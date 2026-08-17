package pcrlock

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// createTestLUKS2ImagePcrlock creates a temporary LUKS2 image for testing.
func createTestLUKS2ImagePcrlock(t *testing.T, jsonContent string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test-luks.img")

	jsonArea := []byte(jsonContent)
	hdrLen := uint64(0x1000 + len(jsonArea))

	binHeader := make([]byte, 0x1000)
	copy(binHeader[0:4], []byte("LUKS"))
	binHeader[4] = 0xba
	binHeader[5] = 0xbe
	binary.BigEndian.PutUint16(binHeader[6:8], 2)
	binary.BigEndian.PutUint64(binHeader[8:16], hdrLen)

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()
	f.Write(binHeader)
	f.Write(jsonArea)

	return path
}

func TestComputeLUKSHeaderDigest_Basic(t *testing.T) {
	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)
	digest, err := computeLUKSHeaderDigest(path)
	if err != nil {
		t.Fatalf("computeLUKSHeaderDigest: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("digest length: got %d, want 32", len(digest))
	}
}

func TestComputeLUKSHeaderDigest_ReadOnly(t *testing.T) {
	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)
	original, _ := os.ReadFile(path)
	_, _ = computeLUKSHeaderDigest(path)
	after, _ := os.ReadFile(path)

	if len(original) != len(after) {
		t.Errorf("File size changed: %d -> %d", len(original), len(after))
	}
	for i := range original {
		if original[i] != after[i] {
			t.Errorf("File modified at byte %d", i)
			break
		}
	}
}

func TestComputeLUKSHeaderDigest_NotLUKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-luks.img")
	os.WriteFile(path, []byte("not LUKS"), 0644)
	_, err := computeLUKSHeaderDigest(path)
	if err == nil {
		t.Error("should fail for non-LUKS file")
	}
}

func TestComputeLUKSHeaderDigest_LUKS1(t *testing.T) {
	header := make([]byte, 32)
	copy(header[0:4], []byte("LUKS"))
	header[4] = 0xba
	header[5] = 0xbe
	binary.BigEndian.PutUint16(header[6:8], 1)
	path := filepath.Join(t.TempDir(), "luks1.img")
	os.WriteFile(path, header, 0644)
	_, err := computeLUKSHeaderDigest(path)
	if err == nil {
		t.Error("should fail for LUKS1")
	}
}

func TestComputeLUKSHeaderDigest_InvalidHdrLen(t *testing.T) {
	header := make([]byte, 32)
	copy(header[0:4], []byte("LUKS"))
	header[4] = 0xba
	header[5] = 0xbe
	binary.BigEndian.PutUint16(header[6:8], 2)
	binary.BigEndian.PutUint64(header[8:16], 0x100)
	path := filepath.Join(t.TempDir(), "bad-luks.img")
	os.WriteFile(path, header, 0644)
	_, err := computeLUKSHeaderDigest(path)
	if err == nil {
		t.Error("should fail for invalid header length")
	}
}

func TestComputeLUKSHeaderDigest_NonexistentDevice(t *testing.T) {
	_, err := computeLUKSHeaderDigest("/dev/nonexistent-99999")
	if err == nil {
		t.Error("should fail for nonexistent device")
	}
}

func TestComputeLUKSHeaderDigest_DifferentHeadersDifferentDigest(t *testing.T) {
	path1 := createTestLUKS2ImagePcrlock(t, `{"keyslots":{"0":{}}}`)
	path2 := createTestLUKS2ImagePcrlock(t, `{"keyslots":{"0":{},"1":{}}}`)
	d1, _ := computeLUKSHeaderDigest(path1)
	d2, _ := computeLUKSHeaderDigest(path2)
	if bytesEqualPcrlock(d1, d2) {
		t.Error("Different headers should produce different digests")
	}
}

func TestComputeLUKSHeaderDigest_Deterministic(t *testing.T) {
	content := `{"keyslots":{"0":{}}}`
	path1 := createTestLUKS2ImagePcrlock(t, content)
	path2 := createTestLUKS2ImagePcrlock(t, content)
	d1, _ := computeLUKSHeaderDigest(path1)
	d2, _ := computeLUKSHeaderDigest(path2)
	if !bytesEqualPcrlock(d1, d2) {
		t.Error("Same header should produce same digest")
	}
}

func TestLockLUKSHeader_CreatesValidPcrlockFile(t *testing.T) {
	// Override PCRLockDir to a temp directory
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{"0":{}}}`)

	if err := LockLUKSHeader(path); err != nil {
		t.Fatalf("LockLUKSHeader: %v", err)
	}

	// Verify the .pcrlock file exists
	pcrlockPath := filepath.Join(PCRLockDir, "755-vanguard-luks-header.pcrlock.d", "luks-header.pcrlock")
	data, err := os.ReadFile(pcrlockPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Parse the .pcrlock file and verify format
	var pcrlockFile map[string]interface{}
	if err := json.Unmarshal(data, &pcrlockFile); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	records, ok := pcrlockFile["records"].([]interface{})
	if !ok || len(records) != 1 {
		t.Fatalf("records: expected 1, got %v", pcrlockFile["records"])
	}

	record := records[0].(map[string]interface{})
	if pcr, ok := record["pcr"].(float64); !ok || int(pcr) != 11 {
		t.Errorf("pcr: expected 11, got %v", record["pcr"])
	}

	digests, ok := record["digests"].([]interface{})
	if !ok || len(digests) != 1 {
		t.Fatalf("digests: expected 1, got %v", record["digests"])
	}

	digest := digests[0].(map[string]interface{})
	if digest["hashAlg"] != "sha256" {
		t.Errorf("hashAlg: expected sha256, got %v", digest["hashAlg"])
	}

	digestStr, ok := digest["digest"].(string)
	if !ok || len(digestStr) != 64 {
		t.Errorf("digest: expected 64-char hex string, got %v", digest["digest"])
	}

	// Verify the digest matches computeLUKSHeaderDigest
	expectedDigest, _ := computeLUKSHeaderDigest(path)
	expectedHex := fmt.Sprintf("%x", expectedDigest)
	if digestStr != expectedHex {
		t.Errorf("digest mismatch: got %s, want %s", digestStr, expectedHex)
	}
}

func TestMaskLUKSHeader_CreatesSymlink(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	if err := MaskLUKSHeader(); err != nil {
		t.Fatalf("MaskLUKSHeader: %v", err)
	}

	// Verify the symlink exists
	linkPath := filepath.Join(PCRLockDir, "755-vanguard-luks-header.pcrlock")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("expected symlink to /dev/null")
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "/dev/null" {
		t.Errorf("symlink target: got %s, want /dev/null", target)
	}
}

func bytesEqualPcrlock(a, b []byte) bool {
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
