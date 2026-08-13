package tpm

import (
	"testing"
	"time"

	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestSwtpmRecoveryEnrollAndRead tests the full recovery seed lifecycle
// using swtpm instead of the real TPM hardware.
func TestSwtpmRecoveryEnrollAndRead(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if !client.WaitForDevice(5 * time.Second) {
		t.Fatal("WaitForDevice should return true with transport set")
	}

	nvIndex := uint32(0x01C30020)

	// Clean up any existing index
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	// Read current PCR 7
	pcrValues := make(map[int][]byte)
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	pcrValues[7] = val

	// Define NV space
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	// Check it exists
	if !client.RecoveryNVExists(nvIndex) {
		t.Fatal("RecoveryNVExists should return true after DefineRecoveryNVSpace")
	}

	// Write recovery data
	testSeed := make([]byte, SeedSize)
	for i := range testSeed {
		testSeed[i] = byte(i)
	}
	testTimestamp := int64(1234567890)
	if err := client.WriteRecoveryData(nvIndex, testSeed, testTimestamp, pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Read recovery data back
	seed, refTimestamp, _, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData: %v", err)
	}

	// Verify seed
	for i, b := range seed {
		if b != byte(i) {
			t.Fatalf("seed[%d]: got %d, want %d", i, b, byte(i))
		}
	}
	if refTimestamp != testTimestamp {
		t.Errorf("timestamp: got %d, want %d", refTimestamp, testTimestamp)
	}

	// Update timestamp
	newTimestamp := int64(9876543210)
	if err := client.UpdateRecoveryTimestamp(newTimestamp); err != nil {
		t.Fatalf("UpdateRecoveryTimestamp: %v", err)
	}

	// Read again - timestamp should be updated, seed preserved
	seed2, refTimestamp2, _, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData after timestamp update: %v", err)
	}
	if refTimestamp2 != newTimestamp {
		t.Errorf("timestamp after update: got %d, want %d", refTimestamp2, newTimestamp)
	}
	// Seed should be unchanged
	for i, b := range seed2 {
		if b != byte(i) {
			t.Fatalf("seed2[%d] changed after timestamp update", i)
		}
	}

	// Undefine
	if err := client.UndefineRecoveryNVSpace(nvIndex, nil); err != nil {
		t.Fatalf("UndefineRecoveryNVSpace: %v", err)
	}

	// Verify it's gone
	if client.RecoveryNVExists(nvIndex) {
		t.Error("RecoveryNVExists should return false after undefine")
	}
}

// TestSwtpmRecoverySeedNotReadable tests that the seed is not readable
// when PCR 7 doesn't match the enrollment value.
func TestSwtpmRecoverySeedNotReadableWrongPCR(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	nvIndex := uint32(0x01C30021)

	// Clean up
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	// Read current PCR 7 and define with a fake value
	pcrValues := make(map[int][]byte)
	val, err := client.ReadPCR(AlgSHA256, 7)
	if err != nil {
		t.Fatalf("ReadPCR 7: %v", err)
	}
	// Use a fake PCR 7 value (different from current)
	fakePCR7 := make([]byte, 32)
	for i := range fakePCR7 {
		fakePCR7[i] = 0xFF
	}
	pcrValues[7] = fakePCR7

	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	// Write with fake PCR values (should work - writeSeedWithPolicy uses current TPM PCR values)
	// Actually this will fail because the policy session uses current PCR values which don't match
	// The authPolicy was computed from fakePCR7, but the TPM's current PCR 7 is different
	// So writeSeedWithPolicy's PolicyPCR will produce a different session digest
	// This is actually the correct behavior - you can only write when PCRs match

	// Instead, let's just verify that ReadRecoveryData fails when PCR doesn't match
	// First, write with the correct PCR values
	pcrValuesCorrect := make(map[int][]byte)
	pcrValuesCorrect[7] = val
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValuesCorrect); err != nil {
		t.Fatalf("DefineRecoveryNVSpace (correct): %v", err)
	}
	testSeed := make([]byte, SeedSize)
	if err := client.WriteRecoveryData(nvIndex, testSeed, 1000, pcrValuesCorrect); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Now redefine with fake PCR 7 - the old seed becomes unreadable
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace (fake): %v", err)
	}

	// Read should fail because PCR 7 doesn't match the authPolicy
	_, _, _, err = client.ReadRecoveryData(nvIndex)
	if err == nil {
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
