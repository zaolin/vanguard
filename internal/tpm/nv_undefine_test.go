package tpm

import (
	"testing"

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
