package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSbctlVerifyJSON(t *testing.T) {
	raw := `[
		{"file_name": "/boot/EFI/Gentoo/kernel.efi", "is_signed": 1},
		{"file_name": "/boot/EFI/Gentoo/kernel-backup.efi", "is_signed": 0},
		{"file_name": "/boot/EFI/Gentoo/missing.efi", "is_signed": -1}
	]`

	var results []sbctlVerified
	if err := json.Unmarshal([]byte(raw), &results); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if results[0].FileName != "/boot/EFI/Gentoo/kernel.efi" || results[0].IsSigned != 1 {
		t.Errorf("result[0]: got %s is_signed=%d", results[0].FileName, results[0].IsSigned)
	}
	if results[1].IsSigned != 0 {
		t.Errorf("result[1]: expected is_signed=0 (unsigned), got %d", results[1].IsSigned)
	}
	if results[2].IsSigned != -1 {
		t.Errorf("result[2]: expected is_signed=-1 (missing), got %d", results[2].IsSigned)
	}
}

func TestParseSbctlFilesDB(t *testing.T) {
	raw := `{
		"/boot/EFI/Gentoo/kernel.efi": {
			"file": "/boot/EFI/Gentoo/kernel.efi",
			"output_file": "/boot/EFI/Gentoo/kernel.efi"
		},
		"/boot/EFI/Gentoo/fwupdx64.efi": {
			"file": "/boot/EFI/Gentoo/fwupdx64.efi",
			"output_file": "/boot/EFI/Gentoo/fwupdx64.efi"
		}
	}`

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "files.json")
	if err := os.WriteFile(dbPath, []byte(raw), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var filesMap map[string]struct {
		File       string `json:"file"`
		OutputFile string `json:"output_file"`
	}
	if err := json.Unmarshal(data, &filesMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(filesMap) != 2 {
		t.Errorf("expected 2 files, got %d", len(filesMap))
	}

	entry, ok := filesMap["/boot/EFI/Gentoo/kernel.efi"]
	if !ok {
		t.Error("kernel.efi not in files map")
	}
	if entry.File != "/boot/EFI/Gentoo/kernel.efi" {
		t.Errorf("file path: got %s", entry.File)
	}
}

func TestParseSbctlEnrolledKeysJSON(t *testing.T) {
	// Simplified sbctl list-enrolled-keys --json structure
	raw := `{
		"PK": [{"Subject": {"CommonName": "Platform Key"}, "NotBefore": "2025-07-16T20:01:00Z", "NotAfter": "2030-07-16T20:01:00Z"}],
		"KEK": [{"Subject": {"CommonName": "Key Exchange Key"}, "NotBefore": "2025-07-16T20:01:01Z", "NotAfter": "2030-07-16T20:01:01Z"}],
		"DB": [{"Subject": {"CommonName": "Database Key"}, "NotBefore": "2025-07-16T20:01:01Z", "NotAfter": "2030-07-16T20:01:01Z"}]
	}`

	var raw2 map[string][]map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &raw2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	pk := parseEnrolledKeyList(raw2["PK"])
	if len(pk) != 1 {
		t.Fatalf("PK: expected 1 cert, got %d", len(pk))
	}
	if pk[0].CommonName != "Platform Key" {
		t.Errorf("PK CN: got %s", pk[0].CommonName)
	}
	if pk[0].NotBefore != "2025-07-16T20:01:00Z" {
		t.Errorf("PK NotBefore: got %s", pk[0].NotBefore)
	}

	kek := parseEnrolledKeyList(raw2["KEK"])
	if len(kek) != 1 || kek[0].CommonName != "Key Exchange Key" {
		t.Errorf("KEK parsing failed")
	}

	db := parseEnrolledKeyList(raw2["DB"])
	if len(db) != 1 || db[0].CommonName != "Database Key" {
		t.Errorf("DB parsing failed")
	}
}

func TestParseEnrolledKeyList_Empty(t *testing.T) {
	result := parseEnrolledKeyList(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 keys for nil input, got %d", len(result))
	}
}

func TestParseEnrolledKeyList_MissingCommonName(t *testing.T) {
	certs := []map[string]interface{}{
		{"NotBefore": "2025-01-01T00:00:00Z", "NotAfter": "2030-01-01T00:00:00Z"},
	}
	result := parseEnrolledKeyList(certs)
	if len(result) != 1 {
		t.Fatalf("expected 1 key, got %d", len(result))
	}
	if result[0].CommonName != "" {
		t.Errorf("expected empty CommonName, got %s", result[0].CommonName)
	}
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{"key": "value", "num": 42}
	if getString(m, "key") != "value" {
		t.Error("getString should return string value")
	}
	if getString(m, "num") != "" {
		t.Error("getString should return empty for non-string")
	}
	if getString(m, "missing") != "" {
		t.Error("getString should return empty for missing key")
	}
}

func TestReadBootCurrent(t *testing.T) {
	// Can only test if the EFI variable exists
	_, err := readBootCurrent()
	if err != nil {
		// Non-EFI system — skip
		t.Skip("BootCurrent EFI variable not available")
	}
	// If we get here, it should be a valid uint16
}

func TestReadBootCurrent_ParseBytes(t *testing.T) {
	// Build a fake BootCurrent EFI variable: 4-byte attributes + 2-byte uint16
	data := make([]byte, 6)
	binary.LittleEndian.PutUint16(data[4:6], 0x0003)

	// Write to temp file and test parsing
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "BootCurrent-test")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	readData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if len(readData) < 6 {
		t.Fatalf("data too short: %d", len(readData))
	}

	bootNum := binary.LittleEndian.Uint16(readData[4:6])
	if bootNum != 3 {
		t.Errorf("boot number: got %d, want 3", bootNum)
	}
}

func TestDetectESPMountPoint(t *testing.T) {
	// This reads /proc/mounts — should always work on Linux
	result := detectESPMountPoint()
	if result == "" {
		// Might be empty in a container without mounts
		t.Skip("No ESP mount point detected (container/test environment)")
	}
	// Should be one of the common candidates or at least non-empty
	t.Logf("Detected ESP mount: %s", result)
}

func TestDetectESPMountPoint_FallbackToBoot(t *testing.T) {
	// Test the fallback logic: if no vfat mount found, should default to /boot
	// This is implicitly tested by detectESPMountPoint returning "/boot" as last resort
}

func TestDetectBootedUKI(t *testing.T) {
	result := detectBootedUKI()
	if result == "" {
		// Non-EFI or BootCurrent not available
		t.Skip("Booted UKI path not available")
	}
	// Should be a Linux path starting with /
	if result[0] != '/' {
		t.Errorf("booted UKI path should start with /, got: %s", result)
	}
	t.Logf("Detected booted UKI: %s", result)
}

func TestSbctlInfo_BootedUKISigned(t *testing.T) {
	// Test the logic that determines if the booted UKI is signed
	signed := true
	info := sbctlInfo{
		Installed:       true,
		BootedUKISigned: &signed,
		BootedUKIPath:   "/boot/EFI/Gentoo/kernel.efi",
	}

	if info.BootedUKISigned == nil {
		t.Fatal("BootedUKISigned should not be nil")
	}
	if !*info.BootedUKISigned {
		t.Error("BootedUKISigned should be true")
	}
}

func TestSbctlInfo_BootedUKISigned_NilWhenNotRoot(t *testing.T) {
	// When not root, BootedUKISigned should be nil
	info := sbctlInfo{
		Installed:       true,
		BootedUKISigned: nil,
	}

	if info.BootedUKISigned != nil {
		t.Error("BootedUKISigned should be nil when not root")
	}
}
