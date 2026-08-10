package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// --- Tests for computeNVName ---

func TestComputeNVName_SpecCompliant(t *testing.T) {
	// Build a proper TPM2B_NV_PUBLIC:
	// [2 size][4 nvIndex][2 nameAlg=SHA256][4 attributes][2 authPolicySize=0][2 dataSize]
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], 14)
	binary.BigEndian.PutUint32(data[2:6], 0x01800001)
	binary.BigEndian.PutUint16(data[6:8], 0x000B)
	binary.BigEndian.PutUint32(data[8:12], 0)
	binary.BigEndian.PutUint16(data[12:14], 0)
	binary.BigEndian.PutUint16(data[14:16], 34)

	name, err := computeNVName(data)
	if err != nil {
		t.Fatalf("computeNVName: %v", err)
	}

	if len(name) != 2+sha256.Size {
		t.Fatalf("name length: %d, want %d", len(name), 2+sha256.Size)
	}

	nameAlg := binary.BigEndian.Uint16(name[0:2])
	if nameAlg != 0x000B {
		t.Errorf("nameAlg = 0x%x, want 0x000B", nameAlg)
	}

	expectedHash := sha256.Sum256(data[2:])
	if hex.EncodeToString(name[2:]) != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("name hash mismatch:\n  got:    %x\n  expect: %x", name[2:], expectedHash[:])
	}
}

func TestComputeNVName_NoTPM2BSize(t *testing.T) {
	data := make([]byte, 14)
	binary.BigEndian.PutUint32(data[0:4], 0x01800001)
	binary.BigEndian.PutUint16(data[4:6], 0x000B)
	binary.BigEndian.PutUint32(data[6:10], 0)
	binary.BigEndian.PutUint16(data[10:12], 0)

	name, err := computeNVName(data)
	if err != nil {
		t.Fatalf("computeNVName: %v", err)
	}

	expectedHash := sha256.Sum256(data)
	if hex.EncodeToString(name[2:]) != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("name hash mismatch (no TPM2B):\n  got:    %x\n  expect: %x", name[2:], expectedHash[:])
	}
}

func TestComputeNVName_TooShort(t *testing.T) {
	_, err := computeNVName([]byte{0x01, 0x80})
	if err == nil {
		t.Error("expected error for short blob, got nil")
	}
}

func TestComputeNVName_UnsupportedNameAlg(t *testing.T) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], 14)
	binary.BigEndian.PutUint32(data[2:6], 0x01800001)
	binary.BigEndian.PutUint16(data[6:8], 0x000C)
	binary.BigEndian.PutUint32(data[8:12], 0)
	binary.BigEndian.PutUint16(data[12:14], 0)
	binary.BigEndian.PutUint16(data[14:16], 34)

	_, err := computeNVName(data)
	if err == nil {
		t.Error("expected error for unsupported nameAlg, got nil")
	}
}

func TestComputeNVName_WithAuthPolicy(t *testing.T) {
	authPolicy := make([]byte, 32)
	for i := range authPolicy {
		authPolicy[i] = byte(i + 1)
	}
	data := make([]byte, 14+32+2)
	binary.BigEndian.PutUint16(data[0:2], 14+32+2-2)
	binary.BigEndian.PutUint32(data[2:6], 0x01ABCDEF)
	binary.BigEndian.PutUint16(data[6:8], 0x000B)
	binary.BigEndian.PutUint32(data[8:12], 0)
	binary.BigEndian.PutUint16(data[12:14], 32)
	copy(data[14:46], authPolicy)
	binary.BigEndian.PutUint16(data[46:48], 34)

	name, err := computeNVName(data)
	if err != nil {
		t.Fatalf("computeNVName with authPolicy: %v", err)
	}

	expectedHash := sha256.Sum256(data[2:])
	if hex.EncodeToString(name[2:]) != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("name hash mismatch (with authPolicy):\n  got:    %x\n  expect: %x", name[2:], expectedHash[:])
	}
}

func TestComputeNVName_DifferentAuthPolicyProducesDifferentName(t *testing.T) {
	makeBlob := func(authPolicyByte byte) []byte {
		data := make([]byte, 48)
		binary.BigEndian.PutUint16(data[0:2], 46)
		binary.BigEndian.PutUint32(data[2:6], 0x01800001)
		binary.BigEndian.PutUint16(data[6:8], 0x000B)
		binary.BigEndian.PutUint32(data[8:12], 0)
		binary.BigEndian.PutUint16(data[12:14], 32)
		for i := 14; i < 46; i++ {
			data[i] = authPolicyByte
		}
		binary.BigEndian.PutUint16(data[46:48], 34)
		return data
	}

	name1, _ := computeNVName(makeBlob(0xAA))
	name2, _ := computeNVName(makeBlob(0xBB))

	if hex.EncodeToString(name1) == hex.EncodeToString(name2) {
		t.Error("different authPolicy should produce different NV name — NV redefinition detection requires this")
	}
}

func TestComputeNVName_VolatileBitsDoNotChangeName(t *testing.T) {
	// The TPM sets TPMA_NV_WRITTEN (bit 29) when the NV index is written.
	// The token captures the TPM2B_NV_PUBLIC before the write (Written=0),
	// but the TPM reports Written=1 after make-policy runs.
	// The name must be the same regardless of these volatile bits.
	makeBlob := func(written, readLocked, writeLocked bool) []byte {
		data := make([]byte, 16)
		binary.BigEndian.PutUint16(data[0:2], 14)
		binary.BigEndian.PutUint32(data[2:6], 0x01800001)
		binary.BigEndian.PutUint16(data[6:8], 0x000B)
		// Build attributes with volatile bits set/clear
		var attrs uint32
		if written {
			attrs |= 1 << 29
		}
		if readLocked {
			attrs |= 1 << 28
		}
		if writeLocked {
			attrs |= 1 << 11
		}
		binary.BigEndian.PutUint32(data[8:12], attrs)
		binary.BigEndian.PutUint16(data[12:14], 0) // authPolicySize = 0
		binary.BigEndian.PutUint16(data[14:16], 34)
		return data
	}

	// Written=0 (token state) vs Written=1 (TPM state after make-policy)
	nameBeforeWrite, _ := computeNVName(makeBlob(false, false, false))
	nameAfterWrite, _ := computeNVName(makeBlob(true, false, false))

	if hex.EncodeToString(nameBeforeWrite) != hex.EncodeToString(nameAfterWrite) {
		t.Error("NV name should be identical regardless of Written bit — volatile bits must be masked")
	}

	// ReadLocked and WriteLocked should also not affect the name
	nameLocked, _ := computeNVName(makeBlob(true, true, true))
	if hex.EncodeToString(nameBeforeWrite) != hex.EncodeToString(nameLocked) {
		t.Error("NV name should be identical regardless of ReadLocked/WriteLocked bits")
	}
}

func TestComputeNVName_NonVolatileBitsChangeName(t *testing.T) {
	// Non-volatile attributes (e.g. PolicyWrite, OwnerRead) MUST change the
	// name — they are part of the NV index identity and cannot be spoofed.
	makeBlob := func(policyWrite bool) []byte {
		data := make([]byte, 16)
		binary.BigEndian.PutUint16(data[0:2], 14)
		binary.BigEndian.PutUint32(data[2:6], 0x01800001)
		binary.BigEndian.PutUint16(data[6:8], 0x000B)
		var attrs uint32
		if policyWrite {
			attrs |= 1 << 3 // PolicyWrite bit
		}
		binary.BigEndian.PutUint32(data[8:12], attrs)
		binary.BigEndian.PutUint16(data[12:14], 0)
		binary.BigEndian.PutUint16(data[14:16], 34)
		return data
	}

	name1, _ := computeNVName(makeBlob(false))
	name2, _ := computeNVName(makeBlob(true))

	if hex.EncodeToString(name1) == hex.EncodeToString(name2) {
		t.Error("different PolicyWrite attribute should produce different NV name — spoofing detection requires this")
	}
}

// --- Tests for policy digest algorithm validation ---

func TestComputePolicyPCRHash_RejectsNonSHA256(t *testing.T) {
	sel := tpm2.TPMLPCRSelection{}
	_, err := computePolicyPCRHash(AlgSHA384, nil, nil, sel)
	if err == nil {
		t.Error("expected error for SHA384, got nil")
	}
}

func TestComputePolicyORHash_RejectsNonSHA256(t *testing.T) {
	_, err := computePolicyORHash(AlgSHA384, nil)
	if err == nil {
		t.Error("expected error for SHA384, got nil")
	}
}

func TestComputePolicyPCRHash_AcceptsSHA256(t *testing.T) {
	sel := tpm2.TPMLPCRSelection{}
	_, err := computePolicyPCRHash(AlgSHA256, nil, nil, sel)
	if err != nil {
		t.Errorf("expected no error for SHA256, got: %v", err)
	}
}

func TestComputePolicyORHash_AcceptsSHA256(t *testing.T) {
	branches := [][]byte{make([]byte, 32)}
	_, err := computePolicyORHash(AlgSHA256, branches)
	if err != nil {
		t.Errorf("expected no error for SHA256, got: %v", err)
	}
}

// --- Test for ErrPolicyFailed sentinel ---

func TestErrPolicyFailed_IsDistinguishable(t *testing.T) {
	// ErrPolicyFailed should be distinguishable from ErrTPMLockout
	// (callers need to check for lockout to decide whether to retry)
	// but NOT distinguishable from ErrWrongPIN/ErrPCRMismatch for pcrlock
	if ErrPolicyFailed == ErrWrongPIN {
		t.Error("ErrPolicyFailed should not be the same as ErrWrongPIN")
	}
	if ErrPolicyFailed == ErrPCRMismatch {
		t.Error("ErrPolicyFailed should not be the same as ErrPCRMismatch")
	}
	if ErrPolicyFailed == ErrTPMLockout {
		t.Error("ErrPolicyFailed should not be the same as ErrTPMLockout")
	}
}

// --- Tests for computeSeedReadPolicy ---

func TestComputeSeedReadPolicy_SingleBranch(t *testing.T) {
	// Simulate PCR values at enrollment time
	pcrValues := map[int][]byte{
		0: bytes32(0xAA),
		4: bytes32(0xBB),
		7: bytes32(0xCC),
	}

	policy, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy: %v", err)
	}

	if len(policy) != 32 {
		t.Fatalf("policy digest length: %d, want 32", len(policy))
	}

	// Policy should change when PCR 7 changes (the only PCR in the branch)
	pcrValues2 := map[int][]byte{
		0: bytes32(0xAA),
		4: bytes32(0xBB),
		7: bytes32(0xDD), // PCR 7 changed
	}
	policy2, _ := computeSeedReadPolicy(AlgSHA256, pcrValues2)
	if hex.EncodeToString(policy) == hex.EncodeToString(policy2) {
		t.Error("policy should change when PCR 7 changes")
	}

	// Policy should NOT change when PCR 0 changes (not in the single-branch policy)
	pcrValues3 := map[int][]byte{
		0: bytes32(0xEE), // PCR 0 changed
		4: bytes32(0xBB),
		7: bytes32(0xCC),
	}
	policy3, _ := computeSeedReadPolicy(AlgSHA256, pcrValues3)
	if hex.EncodeToString(policy) != hex.EncodeToString(policy3) {
		t.Error("policy should NOT change when only PCR 0 changes (not in single-branch policy)")
	}

	// Policy should NOT change when PCR 4 changes (not in the single-branch policy)
	pcrValues4 := map[int][]byte{
		0: bytes32(0xAA),
		4: bytes32(0xFF), // PCR 4 changed
		7: bytes32(0xCC),
	}
	policy4, _ := computeSeedReadPolicy(AlgSHA256, pcrValues4)
	if hex.EncodeToString(policy) != hex.EncodeToString(policy4) {
		t.Error("policy should NOT change when only PCR 4 changes (not in single-branch policy)")
	}
}

func TestComputeSeedReadPolicy_RejectsNonSHA256(t *testing.T) {
	pcrValues := map[int][]byte{7: bytes32(0xCC)}
	_, err := computeSeedReadPolicy(AlgSHA384, pcrValues)
	if err == nil {
		t.Error("expected error for SHA384")
	}
}

func TestComputeSeedReadPolicy_MissingPCR(t *testing.T) {
	// Missing PCR 7 (required by all branches)
	pcrValues := map[int][]byte{
		0: bytes32(0xAA),
		4: bytes32(0xBB),
	}
	_, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err == nil {
		t.Error("expected error for missing PCR 7")
	}
}

func TestSeedReadPolicyPCRs_AllBranchesContainPCR7(t *testing.T) {
	for i, pcrSet := range SeedReadPolicyPCRs {
		has7 := false
		for _, pcr := range pcrSet {
			if pcr == 7 {
				has7 = true
			}
		}
		if !has7 {
			t.Errorf("branch %d %v does not contain PCR 7 — all branches must require Secure Boot", i, pcrSet)
		}
	}
}

// bytes32 creates a 32-byte slice filled with the given byte value.
func bytes32(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}
