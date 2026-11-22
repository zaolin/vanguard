package tpm

import (
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestRoundtripDoesNotConsumeDAAttempts pins that the status roundtrip is
// free of dictionary-attack side effects: it must not change the lockout
// counter, even across several runs.
func TestRoundtripDoesNotConsumeDAAttempts(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	before, err := client.GetLockoutStatus()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := client.SealUnsealRoundtrip(); err != nil {
			t.Fatalf("roundtrip %d: %v", i, err)
		}
	}

	after, err := client.GetLockoutStatus()
	if err != nil {
		t.Fatal(err)
	}
	if after.LockoutCounter != before.LockoutCounter {
		t.Errorf("DA counter changed: %d -> %d", before.LockoutCounter, after.LockoutCounter)
	}
	if after.InLockout {
		t.Error("the roundtrip drove the TPM into lockout")
	}
}

// TestRoundtripLeavesNoTransientObjects pins that the roundtrip cleans up
// after itself: repeated status runs must not accumulate transient objects in
// the TPM (which would eventually fail with OBJECT_MEMORY).
func TestRoundtripLeavesNoTransientObjects(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	transientCount := func() int {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      0x80000000, // TPM_HT_TRANSIENT
			PropertyCount: 64,
		}.Execute(tpmTransport)
		if err != nil {
			t.Fatalf("GetCapability(handles): %v", err)
		}
		handles, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			t.Fatalf("decode handles: %v", err)
		}
		return len(handles.Handle)
	}

	before := transientCount()
	for i := 0; i < 3; i++ {
		if err := client.SealUnsealRoundtrip(); err != nil {
			t.Fatalf("roundtrip %d: %v", i, err)
		}
	}
	after := transientCount()

	if after != before {
		t.Errorf("transient objects leaked: %d before, %d after", before, after)
	}
}
