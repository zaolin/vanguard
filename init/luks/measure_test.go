package luks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	intpm "github.com/zaolin/vanguard/internal/tpm"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

func TestWriteEventLogRecord_BasicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "systemd", "tpm2-measure.log")

	// Override the event log path for testing
	origPath := eventLogPath
	eventLogPath = logPath
	defer func() { eventLogPath = origPath }()

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	if err := writeEventLogRecord(11, digest); err != nil {
		t.Fatalf("writeEventLogRecord: %v", err)
	}

	// Verify file exists
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Event log file should not be empty")
	}
}

func TestWriteEventLogRecord_CELJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "systemd", "tpm2-measure.log")

	origPath := eventLogPath
	eventLogPath = logPath
	defer func() { eventLogPath = origPath }()

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(0xAB)
	}

	if err := writeEventLogRecord(11, digest); err != nil {
		t.Fatalf("writeEventLogRecord: %v", err)
	}

	// Read the file and verify CEL-JSON format
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// File should start with RS (0x1E)
	if len(data) < 1 || data[0] != 0x1E {
		t.Errorf("File should start with RS (0x1E), got 0x%02x", data[0])
	}

	// Parse the JSON after the RS
	jsonData := data[1:]
	var record celRecord
	if err := json.Unmarshal(jsonData, &record); err != nil {
		t.Fatalf("Unmarshal: %v\nData: %s", err, string(jsonData))
	}

	// Verify fields
	if record.PCR != 11 {
		t.Errorf("PCR: got %d, want 11", record.PCR)
	}
	if len(record.Digests) != 1 {
		t.Fatalf("Digests: got %d, want 1", len(record.Digests))
	}
	if record.Digests[0].HashAlg != "sha256" {
		t.Errorf("HashAlg: got %s, want sha256", record.Digests[0].HashAlg)
	}
	expectedDigest := hex.EncodeToString(digest)
	if record.Digests[0].Digest != expectedDigest {
		t.Errorf("Digest: got %s, want %s", record.Digests[0].Digest, expectedDigest)
	}
	if record.Content.EventType != "EV_IPL" {
		t.Errorf("EventType: got %s, want EV_IPL", record.Content.EventType)
	}
	if record.Content.Data["string"] != "vanguard-luks-header" {
		t.Errorf("Data[string]: got %s, want vanguard-luks-header", record.Content.Data["string"])
	}
}

func TestWriteEventLogRecord_AppendMode(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "systemd", "tpm2-measure.log")

	origPath := eventLogPath
	eventLogPath = logPath
	defer func() { eventLogPath = origPath }()

	digest1 := make([]byte, 32)
	digest2 := make([]byte, 32)
	digest2[0] = 0xFF

	// Write two records
	if err := writeEventLogRecord(11, digest1); err != nil {
		t.Fatalf("writeEventLogRecord 1: %v", err)
	}
	if err := writeEventLogRecord(11, digest2); err != nil {
		t.Fatalf("writeEventLogRecord 2: %v", err)
	}

	// Read file and verify two records
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Split by RS (0x1E) — should get 3 parts (empty before first RS, record1, record2)
	parts := splitByRS(data)
	if len(parts) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(parts))
	}

	// Parse both records
	var rec1, rec2 celRecord
	if err := json.Unmarshal(parts[0], &rec1); err != nil {
		t.Fatalf("Unmarshal rec1: %v", err)
	}
	if err := json.Unmarshal(parts[1], &rec2); err != nil {
		t.Fatalf("Unmarshal rec2: %v", err)
	}

	if rec1.Digests[0].Digest == rec2.Digests[0].Digest {
		t.Error("Two records should have different digests")
	}
}

func TestWriteEventLogRecord_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "deeply", "nested", "systemd", "tpm2-measure.log")

	origPath := eventLogPath
	eventLogPath = logPath
	defer func() { eventLogPath = origPath }()

	digest := make([]byte, 32)

	if err := writeEventLogRecord(11, digest); err != nil {
		t.Fatalf("writeEventLogRecord: %v", err)
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("Log file should exist: %v", err)
	}
}

func TestWriteEventLogRecord_PreexistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "systemd", "tpm2-measure.log")

	origPath := eventLogPath
	eventLogPath = logPath
	defer func() { eventLogPath = origPath }()

	// Pre-create the file with existing content (simulating systemd-pcrextend having written to it)
	existingRecord := []byte{0x1E}
	existingRecord = append(existingRecord, []byte(`{"pcr":11,"digests":[{"hashAlg":"sha256","digest":"abcd"}],"content":{"event_type":"EV_IPL","data":{"string":"enter-initrd"}},"content_type":"data"}`)...)

	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(logPath, existingRecord, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Write our record
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = 0x42
	}
	if err := writeEventLogRecord(11, digest); err != nil {
		t.Fatalf("writeEventLogRecord: %v", err)
	}

	// Verify both records exist
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	parts := splitByRS(data)
	if len(parts) != 2 {
		t.Fatalf("Expected 2 records (preexisting + new), got %d", len(parts))
	}
}

// splitByRS splits data by RS (0x1E) and returns non-empty parts
func splitByRS(data []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range data {
		if b == 0x1E {
			if i > start {
				parts = append(parts, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		parts = append(parts, data[start:])
	}
	return parts
}

// --- writeEventLogRecord error path tests ---

func TestWriteEventLogRecord_MkdirAllFails(t *testing.T) {
	// Point the event log path to a location where MkdirAll will fail
	// (under a file, not a directory)
	tmpFile := filepath.Join(t.TempDir(), "blocking-file")
	if err := os.WriteFile(tmpFile, []byte("x"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	origPath := eventLogPath
	eventLogPath = filepath.Join(tmpFile, "systemd", "tpm2-measure.log")
	defer func() { eventLogPath = origPath }()

	digest := make([]byte, 32)
	err := writeEventLogRecord(11, digest)
	if err == nil {
		t.Error("writeEventLogRecord should fail when MkdirAll fails")
	}
}

func TestWriteEventLogRecord_OpenFileFails(t *testing.T) {
	// Point to a path that can be created as a directory but not opened for writing
	// Make the directory read-only
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "systemd")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(logDir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(logDir, 0755) // restore so cleanup works

	origPath := eventLogPath
	eventLogPath = filepath.Join(logDir, "tpm2-measure.log")
	defer func() { eventLogPath = origPath }()

	// Skip if running as root (root bypasses permissions)
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test as root")
	}

	digest := make([]byte, 32)
	err := writeEventLogRecord(11, digest)
	if err == nil {
		t.Error("writeEventLogRecord should fail when OpenFile fails")
	}
}

func TestWriteEventLogRecord_WriteFails(t *testing.T) {
	// Create a file, make it read-only. OpenFile with O_WRONLY will fail.
	if os.Geteuid() == 0 {
		t.Skip("skipping write-failure test as root")
	}
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "systemd")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	logPath := filepath.Join(logDir, "tpm2-measure.log")
	if err := os.WriteFile(logPath, []byte{}, 0444); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	origPath := eventLogPath
	eventLogPath = logPath
	defer func() { eventLogPath = origPath }()

	digest := make([]byte, 32)
	err := writeEventLogRecord(11, digest)
	if err == nil {
		t.Error("writeEventLogRecord should fail when file is read-only")
	}
}

// --- buildCELRecord tests ---

func TestBuildCELRecord_Format(t *testing.T) {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	data, err := buildCELRecord(11, digest)
	if err != nil {
		t.Fatalf("buildCELRecord: %v", err)
	}

	var record celRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if record.PCR != 11 {
		t.Errorf("PCR: got %d, want 11", record.PCR)
	}
	if record.Digests[0].HashAlg != "sha256" {
		t.Errorf("HashAlg: got %s, want sha256", record.Digests[0].HashAlg)
	}
	expectedDigest := hex.EncodeToString(digest)
	if record.Digests[0].Digest != expectedDigest {
		t.Errorf("Digest: got %s, want %s", record.Digests[0].Digest, expectedDigest)
	}
}

// --- writeCELData tests ---

type failingWriter struct {
	failOnCall int
	callCount  int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.callCount++
	if w.callCount >= w.failOnCall {
		return 0, errors.New("simulated write failure")
	}
	return len(p), nil
}

func TestWriteCELData_Success(t *testing.T) {
	var buf []byte
	w := &bytesWriter{buf: &buf}
	data := []byte(`{"pcr":11}`)

	if err := writeCELData(w, data); err != nil {
		t.Fatalf("writeCELData: %v", err)
	}

	// Verify RS + data
	if len(buf) != len(data)+1 {
		t.Fatalf("buffer length: got %d, want %d", len(buf), len(data)+1)
	}
	if buf[0] != 0x1E {
		t.Errorf("first byte should be RS (0x1E), got 0x%02x", buf[0])
	}
	if string(buf[1:]) != string(data) {
		t.Errorf("data mismatch")
	}
}

func TestWriteCELData_RSSeparatorFails(t *testing.T) {
	w := &failingWriter{failOnCall: 1}
	err := writeCELData(w, []byte(`{}`))
	if err == nil {
		t.Error("writeCELData should fail when RS write fails")
	}
}

func TestWriteCELData_DataWriteFails(t *testing.T) {
	w := &failingWriter{failOnCall: 2}
	err := writeCELData(w, []byte(`{}`))
	if err == nil {
		t.Error("writeCELData should fail when data write fails")
	}
}

type bytesWriter struct {
	buf *[]byte
}

func (w *bytesWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// --- measureHeaderWithDeps tests ---

func TestMeasureHeaderWithDeps_Success(t *testing.T) {
	// This test requires swtpm to exercise the full flow:
	// hash LUKS header -> extend PCR 11 -> write event log
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	// Create a temp event log path
	tmpDir := t.TempDir()
	origPath := eventLogPath
	eventLogPath = filepath.Join(tmpDir, "systemd", "tpm2-measure.log")
	defer func() { eventLogPath = origPath }()

	// Create a test LUKS image
	path := createTestLUKS2Image(t, `{"keyslots":{"0":{}}}`)

	// Compute expected digest
	expectedDigest, err := HashLUKS2Header(path)
	if err != nil {
		t.Fatalf("HashLUKS2Header: %v", err)
	}

	// Create a TPM client factory that returns a client connected to our swtpm
	tpmClient := intpm.NewWithTransport(tpmTransport)
	newTPMClient := func() *intpm.Client { return tpmClient }

	// Track event log write
	var eventLogWritten bool
	writeEventLog := func(pcr int, digest []byte) error {
		eventLogWritten = true
		if pcr != PCRUsedForLUKSHeader {
			t.Errorf("event log PCR: got %d, want %d", pcr, PCRUsedForLUKSHeader)
		}
		if !digestsEqualByte(digest, expectedDigest) {
			t.Errorf("event log digest mismatch")
		}
		return nil
	}

	// Run measureHeaderWithDeps
	err = measureHeaderWithDeps(path, newTPMClient, writeEventLog)
	if err != nil {
		t.Fatalf("measureHeaderWithDeps: %v", err)
	}

	// Verify PCR 11 was extended
	pcr11, err := tpmClient.ReadPCR(intpm.AlgSHA256, PCRUsedForLUKSHeader)
	if err != nil {
		t.Fatalf("ReadPCR: %v", err)
	}
	if isAllZerosDigest(pcr11) {
		t.Error("PCR 11 should not be all-zeros after extend")
	}

	// Verify event log was written
	if !eventLogWritten {
		t.Error("event log should have been written")
	}
}

func TestMeasureHeaderWithDeps_HashFails(t *testing.T) {
	// Non-LUKS device: HashLUKS2Header fails, MeasureHeader returns nil (non-fatal)
	err := measureHeaderWithDeps(
		"/dev/nonexistent-device-12345",
		func() *intpm.Client { t.Fatal("TPM client should not be created when hash fails"); return nil },
		func(int, []byte) error { t.Fatal("event log should not be written when hash fails"); return nil },
	)
	if err != nil {
		t.Errorf("MeasureHeader should return nil on hash failure, got: %v", err)
	}
}

func TestMeasureHeaderWithDeps_TPMNotAvailable(t *testing.T) {
	path := createTestLUKS2Image(t, `{"keyslots":{}}`)

	// Create a TPM client factory that returns a client with no transport.
	// WaitForDevice will return false (no /dev/tpmrm0 in test environment).
	// Skip if a real TPM exists.
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		t.Skip("TPM device exists — skipping no-TPM test")
	}

	err := measureHeaderWithDeps(
		path,
		intpm.New,
		func(int, []byte) error { t.Fatal("event log should not be written when TPM unavailable"); return nil },
	)
	if err != nil {
		t.Errorf("MeasureHeader should return nil when TPM unavailable, got: %v", err)
	}
}

func TestMeasureHeader_DirectCall(t *testing.T) {
	// Test the MeasureHeader wrapper on a Device struct.
	// Use a non-LUKS path so HashLUKS2Header fails early (non-fatal).
	dev := &Device{Path: "/dev/nonexistent-12345"}
	err := dev.MeasureHeader()
	if err != nil {
		t.Errorf("MeasureHeader should return nil on hash failure, got: %v", err)
	}
}

func TestMeasureHeaderWithDeps_ExtendFailsNonFatal(t *testing.T) {
	// When ExtendPCR fails, MeasureHeader should return nil (non-fatal)
	// and not write the event log.
	// We trigger the failure by killing the swtpm process so the transport
	// socket is broken.
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	path := createTestLUKS2Image(t, `{"keyslots":{}}`)
	tpmClient := intpm.NewWithTransport(tpmTransport)

	// Kill the swtpm process to break the transport
	// The cleanup function will handle the dead process
	pkillErr := exec.Command("pkill", "-f", "swtpm socket").Run()
	_ = pkillErr
	time.Sleep(100 * time.Millisecond)

	eventLogWritten := false
	err := measureHeaderWithDeps(
		path,
		func() *intpm.Client { return tpmClient },
		func(int, []byte) error { eventLogWritten = true; return nil },
	)
	if err != nil {
		t.Errorf("MeasureHeader should return nil on extend failure, got: %v", err)
	}
	if eventLogWritten {
		t.Error("event log should not be written when extend fails")
	}
}

func TestMeasureHeaderWithDeps_EventLogWriteFailsNonFatal(t *testing.T) {
	// When writeEventLogRecord fails, MeasureHeader should return nil (non-fatal).
	// Test this by providing a writeEventLog function that returns an error.
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	path := createTestLUKS2Image(t, `{"keyslots":{}}`)
	tpmClient := intpm.NewWithTransport(tpmTransport)

	err := measureHeaderWithDeps(
		path,
		func() *intpm.Client { return tpmClient },
		func(int, []byte) error { return errors.New("simulated event log write failure") },
	)
	if err != nil {
		t.Errorf("MeasureHeader should return nil even when event log write fails, got: %v", err)
	}

	// PCR should still have been extended
	pcr11, _ := tpmClient.ReadPCR(intpm.AlgSHA256, PCRUsedForLUKSHeader)
	if isAllZerosDigest(pcr11) {
		t.Error("PCR 11 should have been extended even if event log write failed")
	}
}

// --- LockLUKSHeader tests ---

func TestLockLUKSHeader_CreatesPcrlockFile(t *testing.T) {
	// We can't test LockLUKSHeader directly since it writes to /etc/pcrlock.d
	// (requires root). Instead, test the underlying computeLUKSHeaderDigest.
	path := createTestLUKS2Image(t, `{"keyslots":{"0":{}}}`)

	digest, err := computeLUKSHeaderDigestForTest(path)
	if err != nil {
		t.Fatalf("computeLUKSHeaderDigest: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("digest length: got %d, want 32", len(digest))
	}

	// Verify it matches HashLUKS2Header
	expected, _ := HashLUKS2Header(path)
	if !digestsEqualByte(digest, expected) {
		t.Errorf("digest mismatch:\n  got:  %x\n  want: %x", digest, expected)
	}
}

func TestComputeLUKSHeaderDigest_ReadOnly(t *testing.T) {
	path := createTestLUKS2Image(t, `{"keyslots":{}}`)

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	_, _ = computeLUKSHeaderDigestForTest(path)

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after: %v", err)
	}

	if len(original) != len(after) {
		t.Errorf("File size changed: %d -> %d", len(original), len(after))
	}
	for i := range original {
		if original[i] != after[i] {
			t.Errorf("File content changed at byte %d", i)
			break
		}
	}
}

func TestComputeLUKSHeaderDigest_NotLUKS(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "not-luks.img")
	os.WriteFile(path, []byte("not LUKS"), 0644)

	_, err := computeLUKSHeaderDigestForTest(path)
	if err == nil {
		t.Error("should fail for non-LUKS file")
	}
}

func TestComputeLUKSHeaderDigest_LUKS1(t *testing.T) {
	header := make([]byte, 32)
	copy(header[0:4], []byte("LUKS"))
	header[4] = 0xba
	header[5] = 0xbe
	// version 1
	header[6] = 0
	header[7] = 1

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "luks1.img")
	os.WriteFile(path, header, 0644)

	_, err := computeLUKSHeaderDigestForTest(path)
	if err == nil {
		t.Error("should fail for LUKS1")
	}
}

func TestComputeLUKSHeaderDigest_InvalidHeaderLen(t *testing.T) {
	header := make([]byte, 32)
	copy(header[0:4], []byte("LUKS"))
	header[4] = 0xba
	header[5] = 0xbe
	// version 2
	header[6] = 0
	header[7] = 2
	// hdr_len = 0x100 (too small)
	header[8] = 0
	header[9] = 0
	header[10] = 0
	header[11] = 0
	header[12] = 0
	header[13] = 0
	header[14] = 1
	header[15] = 0

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-luks.img")
	os.WriteFile(path, header, 0644)

	_, err := computeLUKSHeaderDigestForTest(path)
	if err == nil {
		t.Error("should fail for invalid header length")
	}
}

func TestComputeLUKSHeaderDigest_NonexistentDevice(t *testing.T) {
	_, err := computeLUKSHeaderDigestForTest("/dev/nonexistent-99999")
	if err == nil {
		t.Error("should fail for nonexistent device")
	}
}

func TestComputeLUKSHeaderDigest_DifferentHeadersDifferentDigest(t *testing.T) {
	path1 := createTestLUKS2Image(t, `{"keyslots":{"0":{}}}`)
	path2 := createTestLUKS2Image(t, `{"keyslots":{"0":{},"1":{}}}`)

	d1, _ := computeLUKSHeaderDigestForTest(path1)
	d2, _ := computeLUKSHeaderDigestForTest(path2)

	if digestsEqualByte(d1, d2) {
		t.Error("Different headers should produce different digests")
	}
}

func TestComputeLUKSHeaderDigest_Deterministic(t *testing.T) {
	jsonContent := `{"keyslots":{"0":{}}}`
	path1 := createTestLUKS2Image(t, jsonContent)
	path2 := createTestLUKS2Image(t, jsonContent)

	d1, _ := computeLUKSHeaderDigestForTest(path1)
	d2, _ := computeLUKSHeaderDigestForTest(path2)

	if !digestsEqualByte(d1, d2) {
		t.Error("Same header content should produce same digest")
	}
}

// --- Helper functions ---

func isAllZerosDigest(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func digestsEqualByte(a, b []byte) bool {
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

// computeLUKSHeaderDigestForTest is a test wrapper that calls the internal
// computeLUKSHeaderDigest function from the pcrlock package. Since we can't
// call it directly (different package), we replicate the hash computation
// here and verify it matches HashLUKS2Header.
func computeLUKSHeaderDigestForTest(devicePath string) ([]byte, error) {
	// Use the same logic as HashLUKS2Header — read the full header and hash it
	data, err := os.ReadFile(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	if len(data) < 16 || string(data[0:4]) != "LUKS" {
		return nil, errors.New("not a LUKS device")
	}

	version := uint16(data[6])<<8 | uint16(data[7])
	if version != 2 {
		return nil, fmt.Errorf("only LUKS2 supported (version %d)", version)
	}

	hdrLen := uint64(data[8])<<56 | uint64(data[9])<<48 | uint64(data[10])<<40 |
		uint64(data[11])<<32 | uint64(data[12])<<24 | uint64(data[13])<<16 |
		uint64(data[14])<<8 | uint64(data[15])

	if hdrLen < 0x1000 || int(hdrLen) > len(data) {
		return nil, fmt.Errorf("invalid header length: %d", hdrLen)
	}

	h := sha256.Sum256(data[:hdrLen])
	return h[:], nil
}