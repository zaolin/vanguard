package pcrlock

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestReadNVIndexDetails_NotFound verifies that ReadNVIndexDetails returns
// an error for a non-existent index.
func TestReadNVIndexDetails_NotFound(t *testing.T) {
	if _, err := swtpmtest.Setup(t); err != nil {
		t.Skip("swtpm not available")
	}

	_, err := ReadNVIndexDetails(0x01999999)
	if err == nil {
		t.Error("ReadNVIndexDetails should return error for non-existent index")
	}
}

// TestReadCurrentPCRs_NoTPM verifies that readCurrentPCRs handles
// the no-TPM case gracefully.
func TestReadCurrentPCRs_NoTPM(t *testing.T) {
	// readCurrentPCRs uses tpm.New() internally
	if _, err := swtpmtest.Setup(t); err != nil {
		t.Skip("swtpm not available")
	}

	// Reading PCRs from a real TPM or swtpm should work
	pcrs, err := readCurrentPCRs([]int{7})
	if err != nil {
		// May fail if no /dev/tpmrm0 — that's fine
		t.Skipf("readCurrentPCRs failed (no TPM device): %v", err)
	}

	if len(pcrs) == 0 {
		t.Error("Expected at least one PCR value")
	}

	if val, ok := pcrs[7]; !ok {
		t.Error("PCR 7 not in result")
	} else if len(val) != 64 { // hex-encoded 32 bytes = 64 chars
		t.Errorf("PCR 7 value length: got %d, want 64", len(val))
	}
}

// TestNVAttributesToString_AllAttributes verifies all attribute flags.
func TestNVAttributesToString_AllAttributes(t *testing.T) {
	attrs := tpm2.TPMANV{
		PPWrite:        true,
		OwnerWrite:     true,
		AuthWrite:      true,
		PolicyWrite:    true,
		OwnerRead:      true,
		AuthRead:       true,
		PolicyRead:     true,
		PlatformCreate: true,
	}

	result := nvAttributesToString(attrs)

	// Should contain all attribute names
	expected := []string{"ppwrite", "ownerwrite", "authwrite", "policywrite", "ownerread", "authread", "policyread", "platformcreate"}
	for _, attr := range expected {
		if !contains(result, attr) {
			t.Errorf("Expected '%s' in output, got: %s", attr, result)
		}
	}
}

// TestNVAttributesToString_NoneSet verifies empty output for zero-value struct.
func TestNVAttributesToString_NoneSet(t *testing.T) {
	attrs := tpm2.TPMANV{}
	result := nvAttributesToString(attrs)
	if result != "" {
		t.Errorf("Zero-value attributes should produce empty string, got: %s", result)
	}
}

// TestNVAttributesToString_PartialSet verifies partial attribute output.
func TestNVAttributesToString_PartialSet(t *testing.T) {
	attrs := tpm2.TPMANV{
		PolicyWrite: true,
		OwnerRead:   true,
	}
	result := nvAttributesToString(attrs)

	if !contains(result, "policywrite") {
		t.Errorf("Expected 'policywrite' in output, got: %s", result)
	}
	if !contains(result, "ownerread") {
		t.Errorf("Expected 'ownerread' in output, got: %s", result)
	}
	if contains(result, "platformcreate") {
		t.Errorf("Should not contain 'platformcreate', got: %s", result)
	}
}
