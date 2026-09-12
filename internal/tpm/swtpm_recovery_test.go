package tpm

import (
	"testing"
	"time"

	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestSwtpmRecoveryEnrollAndRead tests the full recovery seed + state
// lifecycle using swtpm instead of the real TPM hardware.
func TestSwtpmRecoveryEnrollAndRead(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30020)
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	pcrValues := make(map[int][]byte)
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	if !client.RecoveryNVExists(nvIndex) {
		t.Fatal("RecoveryNVExists should return true after DefineRecoveryNVSpace")
	}
	if !client.StateNVExists() {
		t.Fatal("StateNVExists should return true after DefineRecoveryNVSpace")
	}

	testSeed := make([]byte, SeedSize)
	for i := range testSeed {
		testSeed[i] = byte(i)
	}
	if err := client.WriteRecoveryData(nvIndex, testSeed, pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	seed, counter, failCount, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData: %v", err)
	}
	for i, b := range seed {
		if b != byte(i) {
			t.Fatalf("seed[%d]: got %d, want %d", i, b, byte(i))
		}
	}
	if counter != 0 || failCount != 0 {
		t.Errorf("initial state: counter=%d failCount=%d, want 0,0", counter, failCount)
	}

	if err := client.WriteRecoveryState(5, 2); err != nil {
		t.Fatalf("WriteRecoveryState: %v", err)
	}
	seed2, counter2, failCount2, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData after state write: %v", err)
	}
	if counter2 != 5 || failCount2 != 2 {
		t.Errorf("state after write: counter=%d failCount=%d, want 5,2", counter2, failCount2)
	}
	for i, b := range seed2 {
		if b != byte(i) {
			t.Fatalf("seed2[%d] changed after state write", i)
		}
	}

	if err := client.UndefineRecoveryNVSpace(nvIndex, nil); err != nil {
		t.Fatalf("UndefineRecoveryNVSpace: %v", err)
	}
	if client.RecoveryNVExists(nvIndex) {
		t.Error("RecoveryNVExists should return false after undefine")
	}
	if client.StateNVExists() {
		t.Error("StateNVExists should return false after undefine")
	}
}

func TestSwtpmRecoverySeedNotReadableWrongPCR(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	nvIndex := uint32(0x01C30021)
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	// Read current PCR 7
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValuesCorrect := map[int][]byte{7: val}

	// Fake PCR 7 (different from current)
	fakePCR7 := make([]byte, 32)
	for i := range fakePCR7 {
		fakePCR7[i] = 0xFF
	}
	pcrValuesFake := map[int][]byte{7: fakePCR7}

	// Enroll with the correct PCR 7 (defines seed + state, writes both).
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValuesCorrect); err != nil {
		t.Fatalf("DefineRecoveryNVSpace (correct): %v", err)
	}
	testSeed := make([]byte, SeedSize)
	if err := client.WriteRecoveryData(nvIndex, testSeed, pcrValuesCorrect); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Readable with the matching PCR state.
	if _, _, _, err := client.ReadRecoveryData(nvIndex); err != nil {
		t.Fatalf("ReadRecoveryData with matching PCR 7 should succeed: %v", err)
	}

	// Replace ONLY the seed index with a fake-PCR-7 policy: the seed
	// becomes unreadable under the current boot state.
	if err := client.DefineSeedNVIndex(nvIndex, pcrValuesFake); err != nil {
		t.Fatalf("DefineSeedNVIndex (fake): %v", err)
	}

	// Seed read must fail (PCR 7 mismatch).
	if _, err := client.ReadSeedOnly(nvIndex); err == nil {
		t.Error("ReadSeedOnly with different PCR 7 should fail")
	}

	// The state index (bound to the real PCR 7) must remain readable.
	if _, _, err := client.ReadRecoveryState(); err != nil {
		t.Errorf("ReadRecoveryState with matching PCR 7 should still succeed: %v", err)
	}

	// Full ReadRecoveryData fails because of the seed.
	if _, _, _, err := client.ReadRecoveryData(nvIndex); err == nil {
		t.Error("ReadRecoveryData should fail when PCR 7 doesn't match authPolicy")
	}

	// Clean up
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
}

// TestSwtpmGetLockoutStatus tests GetLockoutStatus with swtpm.
func TestSwtpmGetLockoutStatus(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	status, err := client.GetLockoutStatus()
	if err != nil {
		t.Fatalf("GetLockoutStatus: %v", err)
	}

	// A fresh swtpm should not be in lockout
	if status.InLockout {
		t.Error("fresh swtpm should not be in lockout")
	}
	if status.MaxAuthFail == 0 {
		t.Error("MaxAuthFail should be non-zero")
	}
}

// TestSwtpmReadPCRs tests reading PCRs from swtpm.
func TestSwtpmReadPCRs(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// Read PCR 7
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	if len(val) != 32 {
		t.Errorf("PCR 7 length: got %d, want 32", len(val))
	}

	// Read multiple PCRs
	result, err := client.ReadPCRs(AlgSHA256, []int{0, 7})
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("ReadPCRs result: expected 2, got %d", len(result))
	}
	if len(result[0]) != 32 || len(result[7]) != 32 {
		t.Error("PCR values should be 32 bytes")
	}
}

// TestSwtpmListNVIndexes tests listing NV indexes from swtpm.
func TestSwtpmListNVIndexes(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// List before defining anything
	indexes, err := client.ListNVIndexes()
	if err != nil {
		t.Fatalf("ListNVIndexes: %v", err)
	}
	initialCount := len(indexes)

	// Define a test NV index
	nvIndex := uint32(0x01C30030)
	pcrValues := make(map[int][]byte)
	val, _ := client.ReadPCR(AlgSHA256, 7)
	pcrValues[7] = val
	_ = client.DefineRecoveryNVSpace(nvIndex, pcrValues)

	// List again
	indexes, err = client.ListNVIndexes()
	if err != nil {
		t.Fatalf("ListNVIndexes after define: %v", err)
	}
	if len(indexes) <= initialCount {
		t.Error("expected more NV indexes after defining one")
	}

	// Verify our index is listed
	if _, ok := indexes[nvIndex]; !ok {
		t.Errorf("NV index 0x%x not found in list", nvIndex)
	}

	// Clean up
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
}
