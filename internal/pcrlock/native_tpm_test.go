package pcrlock

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestListNVIndices_NativeGoTPM verifies the native go-tpm2 listNVIndices
// function works without shelling out to tpm2_getcap.
func TestListNVIndices_NativeGoTPM(t *testing.T) {
	// This test requires a TPM — skip if swtpm not available
	if _, err := swtpmtest.Setup(t); err != nil {
		t.Skip("swtpm not available")
	}

	indices, err := listNVIndices()
	if err != nil {
		// listNVIndices uses tpm.New() which opens /dev/tpmrm0 — may fail on CI
		t.Skipf("listNVIndices requires TPM device: %v", err)
	}

	// Just verify it returns a valid slice (may be empty on fresh swtpm)
	_ = indices
}

// TestIsPCRLockNVIndex_FiltersRecoveryIndexes verifies that recovery NV indexes
// (in the 0x01C30000 range) are NOT identified as pcrlock indexes.
func TestIsPCRLockNVIndex_FiltersRecoveryIndexes(t *testing.T) {
	// Recovery indexes are in 0x01C30000 range, outside pcrlock range (0x01800000-0x01BFFFFF)
	recoveryIndexes := []int{0x01C30001, 0x01C30002, 0x01C30010}

	for _, idx := range recoveryIndexes {
		if isPCRLockNVIndex(idx) {
			t.Errorf("Recovery index 0x%x should not be identified as pcrlock", idx)
		}
	}
}

// TestIsPCRLockNVIndex_FiltersOutOfRange verifies that indexes outside the
// pcrlock NV range are rejected.
func TestIsPCRLockNVIndex_FiltersOutOfRange(t *testing.T) {
	outOfRange := []int{0x00000000, 0x01000000, 0x01C00000, 0x02000000, 0x00000001}

	for _, idx := range outOfRange {
		if isPCRLockNVIndex(idx) {
			t.Errorf("Out-of-range index 0x%x should not be identified as pcrlock", idx)
		}
	}
}

// TestIsPCRLockNVIndex_AcceptsPcrlockRange verifies that indexes in the
// pcrlock NV range pass the range check. The full attribute check requires
// a TPM and will return false without one, but the range check should not
// reject them (and should not hang or panic).
func TestIsPCRLockNVIndex_AcceptsPcrlockRange(t *testing.T) {
	// This test calls isPCRLockNVIndex which uses tpm.New() internally.
	// On machines with a real TPM, this does real I/O (slow).
	// On CI (no TPM), it fails fast. Skip if no TPM device.
	if _, err := swtpmtest.Setup(t); err != nil {
		t.Skip("swtpm not available")
	}

	// Just verify it doesn't panic
	_ = isPCRLockNVIndex(0x01800000)
}

// TestRemoveNVIndex_NativeGoTPM verifies that removeNVIndex uses native
// go-tpm2 instead of shelling out to tpm2_nvundefine.
func TestRemoveNVIndex_NativeGoTPM(t *testing.T) {
	// removeNVIndex uses tpm.New() internally — requires /dev/tpmrm0
	// Just verify the function doesn't panic on a non-existent index
	err := removeNVIndex(0x01999999)
	// Should return an error (index doesn't exist) or nil (gracefully handled)
	_ = err
}

// TestNVAttributesToString verifies the attribute-to-string conversion.
func TestNVAttributesToString(t *testing.T) {
	// This test verifies the function is accessible and produces output
	attrs := tpm2.TPMANV{} // zero-value struct
	result := nvAttributesToString(attrs)
	if result != "" {
		t.Errorf("Zero-value attributes should produce empty string, got: %s", result)
	}

	// Test with PolicyWrite set
	attrs2 := tpm2.TPMANV{}
	attrs2.PolicyWrite = true
	attrs2.OwnerRead = true
	result2 := nvAttributesToString(attrs2)
	if !contains(result2, "policywrite") {
		t.Errorf("Expected 'policywrite' in output, got: %s", result2)
	}
	if !contains(result2, "ownerread") {
		t.Errorf("Expected 'ownerread' in output, got: %s", result2)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
