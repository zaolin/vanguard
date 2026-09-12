package tpm

import (
	"errors"
	"testing"
	"time"

	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// seedOnlyReseedFlow reproduces the atomic-reseed swap exactly as
// runAutoReseed performs it, using the seed-only primitives, so the
// regression tests exercise the same operation sequence as production.
// It resets the counter to 0 (matching the reseed contract).
func seedOnlyReseedFlow(t *testing.T, client *Client, nvIndex uint32) error {
	t.Helper()
	tempNVIndex := nvIndex + 0x100

	// Read PCR 7 for the policy.
	pcrValues := map[int][]byte{}
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	// Generate + stage the new seed at temp index (seed-only).
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	if err := client.DefineSeedNVIndex(tempNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineSeedNVIndex(temp): %v", err)
	}
	if err := client.WriteSeedOnly(tempNVIndex, seed, pcrValues); err != nil {
		t.Fatalf("WriteSeedOnly(temp): %v", err)
	}

	// Swap: replace primary seed (seed-only), clean temp (seed-only), then
	// reset the shared state index (counter=0, failCount=0).
	if err := client.DefineSeedNVIndex(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineSeedNVIndex(primary): %v", err)
	}
	if err := client.WriteSeedOnly(nvIndex, seed, pcrValues); err != nil {
		t.Fatalf("WriteSeedOnly(primary): %v", err)
	}
	if err := client.UndefineSeedNVSpace(tempNVIndex); err != nil {
		t.Fatalf("UndefineSeedNVSpace(temp): %v", err)
	}
	if err := client.DefineStateNVIndex(pcrValues); err != nil {
		t.Fatalf("DefineStateNVIndex: %v", err)
	}
	return nil
}

// TestSeedOnlyReseedSwap_PreservesState is the regression test for the
// reseed bug: the old code's temp cleanup called UndefineRecoveryNVSpace,
// which also deleted the shared state index — leaving seed present +
// state missing after every "successful" reseed. The seed-only flow must
// leave BOTH indexes intact and readable, with the counter reset to 0.
func TestSeedOnlyReseedSwap_PreservesState(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30030)
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	pcrValues := map[int][]byte{}
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	// Provision recovery (full provisioning path).
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	if err := client.WriteRecoveryData(nvIndex, make([]byte, SeedSize), pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}
	// Advance state so we can prove the reseed resets it.
	if err := client.WriteRecoveryState(9, 4); err != nil {
		t.Fatalf("WriteRecoveryState: %v", err)
	}

	// Run the seed-only reseed flow.
	if err := seedOnlyReseedFlow(t, client, nvIndex); err != nil {
		t.Fatalf("seedOnlyReseedFlow: %v", err)
	}

	// Post-swap invariants — the state the old code broke:
	if !client.RecoveryNVExists(nvIndex) {
		t.Error("primary seed index missing after reseed swap")
	}
	if !client.StateNVExists() {
		t.Fatal("REGRESSION: state index deleted by reseed temp cleanup")
	}
	if client.RecoveryNVExists(nvIndex + 0x100) {
		t.Error("temp seed index not cleaned up")
	}

	counter, failCount, err := client.ReadRecoveryState()
	if err != nil {
		t.Fatalf("ReadRecoveryState after reseed: %v", err)
	}
	if counter != 0 || failCount != 0 {
		t.Errorf("reseed should reset state: counter=%d failCount=%d, want 0,0", counter, failCount)
	}

	if _, _, _, err := client.ReadRecoveryData(nvIndex); err != nil {
		t.Fatalf("ReadRecoveryData after reseed: %v", err)
	}
}

// TestDefineSeedNVIndex_TempStagingDoesNotTouchState verifies the core
// primitive invariant: staging a seed at the temp index never destroys the
// shared state index or its contents.
func TestDefineSeedNVIndex_TempStagingDoesNotTouchState(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30031)
	tempNVIndex := nvIndex + 0x100
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
	_ = client.UndefineSeedNVSpace(tempNVIndex)

	pcrValues := map[int][]byte{}
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	if err := client.WriteRecoveryData(nvIndex, make([]byte, SeedSize), pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}
	if err := client.WriteRecoveryState(11, 1); err != nil {
		t.Fatalf("WriteRecoveryState: %v", err)
	}

	// Stage a seed at the temp index (seed-only primitives).
	if err := client.DefineSeedNVIndex(tempNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineSeedNVIndex(temp): %v", err)
	}
	if err := client.WriteSeedOnly(tempNVIndex, make([]byte, SeedSize), pcrValues); err != nil {
		t.Fatalf("WriteSeedOnly(temp): %v", err)
	}

	// State index must be intact with the original values.
	if !client.StateNVExists() {
		t.Fatal("REGRESSION: state index destroyed by temp seed staging")
	}
	counter, failCount, err := client.ReadRecoveryState()
	if err != nil {
		t.Fatalf("ReadRecoveryState after temp staging: %v", err)
	}
	if counter != 11 || failCount != 1 {
		t.Errorf("state changed by temp staging: counter=%d failCount=%d, want 11,1", counter, failCount)
	}

	// Temp cleanup (seed-only) must also preserve the state.
	if err := client.UndefineSeedNVSpace(tempNVIndex); err != nil {
		t.Fatalf("UndefineSeedNVSpace(temp): %v", err)
	}
	if !client.StateNVExists() {
		t.Fatal("REGRESSION: state index destroyed by seed-only temp cleanup")
	}
	counter, failCount, err = client.ReadRecoveryState()
	if err != nil {
		t.Fatalf("ReadRecoveryState after temp cleanup: %v", err)
	}
	if counter != 11 || failCount != 1 {
		t.Errorf("state changed by temp cleanup: counter=%d failCount=%d, want 11,1", counter, failCount)
	}
}

// TestSeedReadErrorClassification verifies the error taxonomy: a policy
// mismatch (wrong PCR state) yields ErrSeedPCRMismatch; anything else is
// ErrSeedReadTransient. Auto-reseed's destructive path keys on this.
func TestSeedReadErrorClassification(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30032)
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	pcrValues := map[int][]byte{}
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	if err := client.WriteRecoveryData(nvIndex, make([]byte, SeedSize), pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Readable seed with the matching PCR state: no error.
	if _, err := client.ReadSeedOnly(nvIndex); err != nil {
		t.Fatalf("ReadSeedOnly with matching PCR: %v", err)
	}

	// Corrupted PCR state (simulate Secure Boot keys changed): the policy
	// session's PCR digest no longer matches the index authPolicy →
	// ErrSeedPCRMismatch.
	//
	// NOTE: a fresh swtpm reports PCR 7 as all-zeros, and the enrolled
	// index above was defined against that (real) value. The wrong-policy
	// index is defined against a NON-zero bogus PCR 7, so neither the
	// all-zeros state nor any other state the simulator can hold matches
	// its authPolicy.
	bogusPCR := make([]byte, 32)
	for i := range bogusPCR {
		bogusPCR[i] = byte(i + 1)
	}
	wrongPCR := map[int][]byte{7: bogusPCR}
	if err := client.DefineSeedNVIndex(nvIndex+0x50, wrongPCR); err != nil {
		t.Fatalf("DefineSeedNVIndex with wrong PCR: %v", err)
	}
	_, err = client.ReadSeedOnly(nvIndex + 0x50)
	if err == nil {
		t.Fatal("expected read failure for mismatched PCR policy")
	}
	if !errors.Is(err, ErrSeedPCRMismatch) {
		t.Errorf("mismatched PCR policy: got %v, want ErrSeedPCRMismatch", err)
	}
	if errors.Is(err, ErrSeedReadTransient) {
		t.Error("policy mismatch must not be classified as transient")
	}
}

// TestStrandedTempSeedDetection documents the stranded-seed case the
// rewritten auto-reseed detects: primary seed missing + temp present.
func TestStrandedTempSeedDetection(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30033)
	tempNVIndex := nvIndex + 0x100
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
	_ = client.UndefineSeedNVSpace(tempNVIndex)

	pcrValues := map[int][]byte{}
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	// Strand: temp seed exists, primary does not.
	if err := client.DefineSeedNVIndex(tempNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineSeedNVIndex(temp): %v", err)
	}

	if client.RecoveryNVExists(nvIndex) {
		t.Fatal("setup: primary index should not exist")
	}
	if !client.RecoveryNVExists(tempNVIndex) {
		t.Fatal("setup: temp index should exist")
	}
}

// TestStateIndexIsPolicyBound is the regression test for the state-index
// hardening: the counter/fail-count index must be PolicyPCR(PCR 7)-bound,
// so a boot with a different PCR 7 (live USB, tampered chain) can neither
// read the state nor reset the failed-attempt cap. Owner auth alone must
// not suffice.
func TestStateIndexIsPolicyBound(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30034)
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	pcrValues := map[int][]byte{}
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	// Enroll against the current (real) PCR 7.
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	if err := client.WriteRecoveryData(nvIndex, make([]byte, SeedSize), pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Verify the state index carries the policy attributes (PolicyRead/
	// PolicyWrite) and a non-empty authPolicy — owner auth alone must not
	// grant access.
	detailed, err := client.ListNVIndexesDetailed()
	if err != nil {
		t.Fatalf("ListNVIndexesDetailed: %v", err)
	}
	for _, info := range detailed {
		if uint32(info.Index) != DefaultRecoveryStateNVIndex {
			continue
		}
		if !info.Attributes.PolicyWrite || !info.Attributes.PolicyRead {
			t.Error("state index must have PolicyWrite+PolicyRead (policy-bound)")
		}
		if info.Attributes.OwnerWrite || info.Attributes.OwnerRead {
			t.Error("state index must NOT have OwnerWrite/OwnerRead")
		}
		if len(info.AuthPolicy) == 0 {
			t.Error("state index must have a non-empty authPolicy")
		}
		return
	}
	t.Fatalf("state index 0x%x not found", DefaultRecoveryStateNVIndex)
}
