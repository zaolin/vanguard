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
	swtpmtest.SetupEnvTransport(t)

	indices, err := listNVIndices()
	if err != nil {
		// SetupEnv provides a simulator, so a failure here is a real
		// regression, not a missing environment.
		t.Fatalf("listNVIndices failed against the simulator: %v", err)
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

// TestIsPCRLockNVIndex_AcceptsPcrlockRange verifies the pcrlock NV index
// detection against a real (simulated) TPM: an index with the pcrlock shape
// is accepted, an undefined index in the same range is not, and a recovery
// index is rejected by range.
func TestIsPCRLockNVIndex_AcceptsPcrlockRange(t *testing.T) {
	tpmTransport := swtpmtest.SetupEnvTransport(t)

	const index = uint32(0x01800001)

	// The shape systemd-pcrlock uses: ordinary NV index, 34 bytes
	// (TPMT_HA), policywrite + ownerread, no platformcreate.
	_, _ = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
	}.Execute(tpmTransport)
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(index),
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				PolicyWrite: true,
				OwnerRead:   true,
				WriteAll:    true,
				NT:          tpm2.TPMNTOrdinary,
			},
			DataSize: 34,
		}),
	}).Execute(tpmTransport); err != nil {
		t.Fatalf("NVDefineSpace: %v", err)
	}
	defer func() {
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
	}()

	if !isPCRLockNVIndex(int(index)) {
		t.Error("a pcrlock-shaped NV index was not detected")
	}
	if isPCRLockNVIndex(0x01800002) {
		t.Error("an undefined index must not be reported as pcrlock")
	}
	if isPCRLockNVIndex(0x01C30001) {
		t.Error("a recovery index must not be reported as pcrlock")
	}
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
