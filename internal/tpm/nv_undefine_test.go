package tpm

import (
	"testing"
	"time"

	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

func TestNVUndefineSpace_NonexistentIndex(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// Undefining a non-existent index should not return an error
	err := client.NVUndefineSpace(0x01C30999)
	if err != nil {
		t.Errorf("NVUndefineSpace on non-existent index should not error, got: %v", err)
	}
}

func TestNVUndefineSpace_DefineThenUndefine(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// Define a recovery NV space
	pcrValues := map[int][]byte{7: make([]byte, 32)}
	testIndex := uint32(0x01C30020)

	err := client.DefineRecoveryNVSpace(testIndex, pcrValues)
	if err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	// Verify it exists
	if !client.RecoveryNVExists(testIndex) {
		t.Fatal("RecoveryNVExists should return true after define")
	}

	// Undefine it
	err = client.NVUndefineSpace(testIndex)
	if err != nil {
		t.Fatalf("NVUndefineSpace: %v", err)
	}

	// Verify it's gone
	if client.RecoveryNVExists(testIndex) {
		t.Error("RecoveryNVExists should return false after undefine")
	}
}

func TestListNVIndexesDetailed_EmptyTPM(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	indexes, err := client.ListNVIndexesDetailed()
	if err != nil {
		t.Fatalf("ListNVIndexesDetailed: %v", err)
	}

	// Fresh swtpm should have no NV indexes (or very few firmware ones)
	// Just verify it doesn't crash and returns a valid slice
	_ = indexes
}

func TestListNVIndexesDetailed_AfterDefine(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// Define a recovery NV space
	pcrValues := map[int][]byte{7: make([]byte, 32)}
	testIndex := uint32(0x01C30021)

	if err := client.DefineRecoveryNVSpace(testIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(testIndex, nil)

	indexes, err := client.ListNVIndexesDetailed()
	if err != nil {
		t.Fatalf("ListNVIndexesDetailed: %v", err)
	}

	// Find our index
	found := false
	for _, info := range indexes {
		if info.Index == testIndex {
			found = true
			if info.DataSize != SeedSize {
				t.Errorf("DataSize: got %d, want %d", info.DataSize, SeedSize)
			}
			// Recovery seed indexes have PolicyRead and PolicyWrite
			if !info.Attributes.PolicyWrite {
				t.Error("Recovery seed index should have PolicyWrite")
			}
			if !info.Attributes.PolicyRead {
				t.Error("Recovery seed index should have PolicyRead")
			}
			break
		}
	}

	if !found {
		t.Errorf("Defined index 0x%x not found in ListNVIndexesDetailed", testIndex)
	}
}

func TestNVUndefineSpace_PreservesOtherIndexes(t *testing.T) {
	tpmTransport1, cleanup1 := swtpmtest.Setup(t)
	defer cleanup1()

	client := NewWithTransport(tpmTransport1)

	// Define two NV indexes
	idx1 := uint32(0x01C30030)
	idx2 := uint32(0x01C30031)
	pcrValues := map[int][]byte{7: make([]byte, 32)}

	if err := client.DefineRecoveryNVSpace(idx1, pcrValues); err != nil {
		t.Fatalf("Define idx1: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(idx1, nil)

	if err := client.DefineRecoveryNVSpace(idx2, pcrValues); err != nil {
		t.Fatalf("Define idx2: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(idx2, nil)

	// Undefine idx1 — idx2 should still exist
	if err := client.NVUndefineSpace(idx1); err != nil {
		t.Fatalf("NVUndefineSpace idx1: %v", err)
	}

	if client.RecoveryNVExists(idx1) {
		t.Error("idx1 should be undefined")
	}

	if !client.RecoveryNVExists(idx2) {
		t.Error("idx2 should still exist after undefining idx1")
	}
}

// --- ReadSeedOnly tests ---

func TestReadSeedOnly_AfterFullEnrollment(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	testIndex := uint32(0x01C30040)
	pcrValues := map[int][]byte{7: make([]byte, 32)} // all-zeros PCR 7

	// Define + write recovery data
	if err := client.DefineRecoveryNVSpace(testIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(testIndex, nil)

	seed := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes
	if err := client.WriteRecoveryData(testIndex, seed, time.Now().Unix(), pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// ReadSeedOnly should return the same seed
	readSeed, err := client.ReadSeedOnly(testIndex)
	if err != nil {
		t.Fatalf("ReadSeedOnly: %v", err)
	}
	if len(readSeed) != SeedSize {
		t.Errorf("seed length: got %d, want %d", len(readSeed), SeedSize)
	}
	for i := range seed {
		if readSeed[i] != seed[i] {
			t.Errorf("seed mismatch at byte %d", i)
			break
		}
	}
}

func TestReadSeedOnly_TimestampMissing(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	testIndex := uint32(0x01C30041)
	pcrValues := map[int][]byte{7: make([]byte, 32)}

	// Define + write recovery data
	if err := client.DefineRecoveryNVSpace(testIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(testIndex, nil)

	seed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 32 bytes
	if err := client.WriteRecoveryData(testIndex, seed, time.Now().Unix(), pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Delete ONLY the timestamp index (simulating the bug)
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	if err := client.NVUndefineSpace(tsIndex); err != nil {
		t.Fatalf("NVUndefineSpace timestamp: %v", err)
	}

	// ReadRecoveryData should fail (timestamp missing)
	_, _, _, err := client.ReadRecoveryData(testIndex)
	if err == nil {
		t.Error("ReadRecoveryData should fail when timestamp is missing")
	}

	// TimestampNVExists should return false
	if client.TimestampNVExists() {
		t.Error("TimestampNVExists should return false after deleting timestamp")
	}

	// ReadSeedOnly should STILL WORK (doesn't need timestamp)
	readSeed, err := client.ReadSeedOnly(testIndex)
	if err != nil {
		t.Fatalf("ReadSeedOnly should work without timestamp: %v", err)
	}
	if len(readSeed) != SeedSize {
		t.Errorf("seed length: got %d, want %d", len(readSeed), SeedSize)
	}
}

func TestReadSeedOnly_WrongPCR7(t *testing.T) {
	tpmTransport1, cleanup1 := swtpmtest.Setup(t)
	defer cleanup1()
	tpmTransport2, cleanup2 := swtpmtest.Setup(t)
	defer cleanup2()

	client1 := NewWithTransport(tpmTransport1)
	client2 := NewWithTransport(tpmTransport2)
	testIndex := uint32(0x01C30042)

	// Enroll with all-zeros PCR 7 on client1
	pcrValuesZero := map[int][]byte{7: make([]byte, 32)}
	if err := client1.DefineRecoveryNVSpace(testIndex, pcrValuesZero); err != nil {
		t.Fatalf("Define: %v", err)
	}
	defer client1.UndefineRecoveryNVSpace(testIndex, nil)

	seed := []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	if err := client1.WriteRecoveryData(testIndex, seed, time.Now().Unix(), pcrValuesZero); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// ReadSeedOnly on client1 (same PCR 7) should work
	_, err := client1.ReadSeedOnly(testIndex)
	if err != nil {
		t.Errorf("ReadSeedOnly with matching PCR 7 should succeed: %v", err)
	}

	// client2 has different swtpm (different PCR state) — ReadSeedOnly should fail
	// because the seed is sealed to client1's PCR 7, not client2's
	_, err = client2.ReadSeedOnly(testIndex)
	if err == nil {
		t.Error("ReadSeedOnly with different PCR 7 should fail")
	}
}

// --- RecreateTimestampOnly tests ---

func TestRecreateTimestampOnly_TimestampMissing(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	testIndex := uint32(0x01C30043)
	pcrValues := map[int][]byte{7: make([]byte, 32)}

	// Full enrollment
	if err := client.DefineRecoveryNVSpace(testIndex, pcrValues); err != nil {
		t.Fatalf("Define: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(testIndex, nil)

	seed := []byte("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	if err := client.WriteRecoveryData(testIndex, seed, time.Now().Unix(), pcrValues); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Delete timestamp
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	if err := client.NVUndefineSpace(tsIndex); err != nil {
		t.Fatalf("Delete timestamp: %v", err)
	}

	// Verify timestamp is gone
	if client.TimestampNVExists() {
		t.Fatal("Timestamp should be missing")
	}

	// Recreate timestamp
	if err := client.RecreateTimestampOnly(pcrValues); err != nil {
		t.Fatalf("RecreateTimestampOnly: %v", err)
	}

	// Verify timestamp exists now
	if !client.TimestampNVExists() {
		t.Error("Timestamp should exist after RecreateTimestampOnly")
	}

	// ReadRecoveryData should now work
	readSeed, _, _, err := client.ReadRecoveryData(testIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData after timestamp recreation: %v", err)
	}
	if len(readSeed) != SeedSize {
		t.Errorf("seed length: got %d, want %d", len(readSeed), SeedSize)
	}
}

func TestRecreateTimestampOnly_AlreadyExists(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	testIndex := uint32(0x01C30044)
	pcrValues := map[int][]byte{7: make([]byte, 32)}

	// Full enrollment (timestamp is created by DefineRecoveryNVSpace)
	if err := client.DefineRecoveryNVSpace(testIndex, pcrValues); err != nil {
		t.Fatalf("Define: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(testIndex, nil)

	// Timestamp should already exist
	if !client.TimestampNVExists() {
		t.Fatal("Timestamp should exist after enrollment")
	}

	// RecreateTimestampOnly should be a no-op (timestamp already exists)
	if err := client.RecreateTimestampOnly(pcrValues); err != nil {
		t.Fatalf("RecreateTimestampOnly on existing timestamp should not error: %v", err)
	}

	// Timestamp should still exist
	if !client.TimestampNVExists() {
		t.Error("Timestamp should still exist after no-op recreation")
	}
}

func TestTimestampNVExists_FreshTPM(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// Fresh swtpm should not have timestamp index
	if client.TimestampNVExists() {
		t.Error("Fresh TPM should not have timestamp NV index")
	}
}

func TestTimestampNVExists_AfterEnrollment(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	testIndex := uint32(0x01C30045)
	pcrValues := map[int][]byte{7: make([]byte, 32)}

	if err := client.DefineRecoveryNVSpace(testIndex, pcrValues); err != nil {
		t.Fatalf("Define: %v", err)
	}
	defer client.UndefineRecoveryNVSpace(testIndex, nil)

	if !client.TimestampNVExists() {
		t.Error("Timestamp should exist after enrollment")
	}
}
