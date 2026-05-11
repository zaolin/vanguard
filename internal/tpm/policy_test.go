package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestComputePCRDigest(t *testing.T) {
	pcr0 := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	pcr7 := decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00")

	pcrValues := map[int][]byte{0: pcr0, 7: pcr7}

	digest, err := computePCRDigest(AlgSHA256, pcrValues, []int{0, 7})
	if err != nil {
		t.Fatalf("computePCRDigest: %v", err)
	}

	expected := sha256.Sum256(append(pcr0, pcr7...))
	if !equalBytes(digest, expected[:]) {
		t.Errorf("computePCRDigest mismatch:\n  got:  %x\n  want: %x", digest, expected[:])
	}
}

func TestComputePCRDigestSinglePCR(t *testing.T) {
	pcr7 := decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00")

	pcrValues := map[int][]byte{7: pcr7}

	digest, err := computePCRDigest(AlgSHA256, pcrValues, []int{7})
	if err != nil {
		t.Fatalf("computePCRDigest: %v", err)
	}

	expected := sha256.Sum256(pcr7)
	if !equalBytes(digest, expected[:]) {
		t.Errorf("computePCRDigest mismatch:\n  got:  %x\n  want: %x", digest, expected[:])
	}
}

func TestComputePCRDigestMissingPCR(t *testing.T) {
	pcrValues := map[int][]byte{7: []byte("test")}
	_, err := computePCRDigest(AlgSHA256, pcrValues, []int{0, 7})
	if err == nil {
		t.Error("expected error for missing PCR 0")
	}
}

func TestBuildPCRLSelection(t *testing.T) {
	sel := buildPCRLSelection(AlgSHA256, []int{0, 7})

	if len(sel.PCRSelections) != 1 {
		t.Fatalf("expected 1 PCRSelection, got %d", len(sel.PCRSelections))
	}
	if sel.PCRSelections[0].Hash != AlgSHA256 {
		t.Errorf("expected SHA256 bank, got 0x%x", sel.PCRSelections[0].Hash)
	}
	bitmap := sel.PCRSelections[0].PCRSelect
	if len(bitmap) != 3 {
		t.Fatalf("expected 3-byte bitmap, got %d", len(bitmap))
	}
	// PCR 0: byte 0, bit 0 → 0x01; PCR 7: byte 0, bit 7 → 0x80
	if bitmap[0] != 0x81 {
		t.Errorf("byte 0: expected 0x81 (PCR 0 + PCR 7), got 0x%02x", bitmap[0])
	}
	if bitmap[1] != 0x00 {
		t.Errorf("byte 1: expected 0x00, got 0x%02x", bitmap[1])
	}
}

func TestComputePolicyPCRHash(t *testing.T) {
	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}

	sel := buildPCRLSelection(AlgSHA256, []int{0, 7})

	digest, err := computePolicyPCRHash(AlgSHA256, nil, pcrDigest, sel)
	if err != nil {
		t.Fatalf("computePolicyPCRHash: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}

	var zeroDigest [32]byte
	if equalBytes(digest, zeroDigest[:]) {
		t.Error("digest should not be all zeros")
	}
}

func TestComputePolicyPCRHashWithCurrentDigest(t *testing.T) {
	pcrDigest := make([]byte, 32)
	currentDigest := make([]byte, 32)
	for i := range currentDigest {
		currentDigest[i] = byte(0xff - i)
	}

	sel := buildPCRLSelection(AlgSHA256, []int{7})

	digestFromZero, err := computePolicyPCRHash(AlgSHA256, nil, pcrDigest, sel)
	if err != nil {
		t.Fatalf("computePolicyPCRHash from zero: %v", err)
	}

	digestFromCurrent, err := computePolicyPCRHash(AlgSHA256, currentDigest, pcrDigest, sel)
	if err != nil {
		t.Fatalf("computePolicyPCRHash from current: %v", err)
	}

	if equalBytes(digestFromZero, digestFromCurrent) {
		t.Error("digests from different starting states should differ")
	}
}

func TestComputePolicyORHash(t *testing.T) {
	branch1 := make([]byte, 32)
	branch1[0] = 0x01
	branch2 := make([]byte, 32)
	branch2[0] = 0x02

	digest, err := computePolicyORHash(AlgSHA256, [][]byte{branch1, branch2})
	if err != nil {
		t.Fatalf("computePolicyORHash: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}

	var zeroDigest [32]byte
	if equalBytes(digest, zeroDigest[:]) {
		t.Error("PolicyOR hash should not be all zeros (it starts from zero then updates)")
	}
}

func TestBuildSuperPCRPolicyOffline_SingleValueOnly(t *testing.T) {
	pcr0 := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	pcr7 := decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00")

	predictions := []PCRPrediction{
		{PCR: 0, Values: [][]byte{pcr0}},
		{PCR: 7, Values: [][]byte{pcr7}},
	}

	digest, err := buildSuperPCRPolicyOffline(AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("buildSuperPCRPolicyOffline: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}
	if equalBytes(digest, make([]byte, 32)) {
		t.Error("digest should not be all zeros")
	}
}

func TestBuildSuperPCRPolicyOffline_MultiValuePCR(t *testing.T) {
	val1 := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	val2 := decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00")

	predictions := []PCRPrediction{
		{PCR: 7, Values: [][]byte{val1, val2}},
	}

	digest, err := buildSuperPCRPolicyOffline(AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("buildSuperPCRPolicyOffline: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}
}

func TestBuildSuperPCRPolicyOffline_MixedSingleAndMultiValue(t *testing.T) {
	pcr0 := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	pcr7v1 := decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00")
	pcr7v2 := decodeHex(t, "ff223344556677889900aabbccddeeff0011223344556677889900aabbccddff")

	predictions := []PCRPrediction{
		{PCR: 0, Values: [][]byte{pcr0}},
		{PCR: 7, Values: [][]byte{pcr7v1, pcr7v2}},
	}

	digest, err := buildSuperPCRPolicyOffline(AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("buildSuperPCRPolicyOffline: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}
}

func TestBuildSuperPCRPolicyOffline_NoPredictions(t *testing.T) {
	digest, err := buildSuperPCRPolicyOffline(AlgSHA256, nil)
	if err != nil {
		t.Fatalf("buildSuperPCRPolicyOffline: %v", err)
	}
	if !equalBytes(digest, make([]byte, 32)) {
		t.Errorf("no predictions should yield zero digest, got %x", digest)
	}
}

func TestBuildSuperPCRPolicyOffline_ConsistentResults(t *testing.T) {
	pcr0 := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	pcr7v1 := decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00")
	pcr7v2 := decodeHex(t, "ff223344556677889900aabbccddeeff0011223344556677889900aabbccddff")

	predictions := []PCRPrediction{
		{PCR: 0, Values: [][]byte{pcr0}},
		{PCR: 7, Values: [][]byte{pcr7v1, pcr7v2}},
	}

	d1, err := buildSuperPCRPolicyOffline(AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	d2, err := buildSuperPCRPolicyOffline(AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if !equalBytes(d1, d2) {
		t.Errorf("same input should produce same digest:\n  d1: %x\n  d2: %x", d1, d2)
	}
}

func TestBuildSuperPCRPolicyOffline_DifferentValuesProduceDifferentDigests(t *testing.T) {
	pcr0a := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	pcr0b := decodeHex(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	d1, err := buildSuperPCRPolicyOffline(AlgSHA256, []PCRPrediction{
		{PCR: 0, Values: [][]byte{pcr0a}},
	})
	if err != nil {
		t.Fatalf("d1: %v", err)
	}

	d2, err := buildSuperPCRPolicyOffline(AlgSHA256, []PCRPrediction{
		{PCR: 0, Values: [][]byte{pcr0b}},
	})
	if err != nil {
		t.Fatalf("d2: %v", err)
	}

	if equalBytes(d1, d2) {
		t.Error("different PCR values should produce different digests")
	}
}

func TestBuildSuperPCRPolicyOffline_MultiValueOrdering(t *testing.T) {
	v1 := decodeHex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	v2 := decodeHex(t, "2222222222222222222222222222222222222222222222222222222222222222")

	// PolicyOR concatenates branch digests in order, so different orderings
	// produce different digests. Both are valid policies for the same PCR
	// variants, but the digest changes. This is expected TPM behavior.
	d1, err := buildSuperPCRPolicyOffline(AlgSHA256, []PCRPrediction{
		{PCR: 7, Values: [][]byte{v1, v2}},
	})
	if err != nil {
		t.Fatalf("d1: %v", err)
	}

	d2, err := buildSuperPCRPolicyOffline(AlgSHA256, []PCRPrediction{
		{PCR: 7, Values: [][]byte{v2, v1}},
	})
	if err != nil {
		t.Fatalf("d2: %v", err)
	}

	// Both should be valid non-zero digests
	if equalBytes(d1, make([]byte, 32)) {
		t.Error("d1 should not be zero")
	}
	if equalBytes(d2, make([]byte, 32)) {
		t.Error("d2 should not be zero")
	}
}

func TestParsePCRLockJSON_Basic(t *testing.T) {
	jsonData := []byte(`{
		"pcrBank": "sha256",
		"nvIndex": 25165824,
		"pcrValues": [
			{"pcr": 0, "values": ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"]},
			{"pcr": 7, "values": ["11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00", "ff223344556677889900aabbccddeeff0011223344556677889900aabbccddff"]}
		]
	}`)

	policy, err := ParsePCRLockJSON(jsonData)
	if err != nil {
		t.Fatalf("ParsePCRLockJSON: %v", err)
	}

	if policy.NVIndex != 25165824 {
		t.Errorf("NVIndex: got %d, want 25165824", policy.NVIndex)
	}
	if policy.Bank != AlgSHA256 {
		t.Errorf("Bank: got 0x%x, want 0x%x", policy.Bank, AlgSHA256)
	}
	if len(policy.PCRPredictions) != 2 {
		t.Fatalf("PCRPredictions: got %d, want 2", len(policy.PCRPredictions))
	}
	if policy.PCRPredictions[0].PCR != 0 {
		t.Errorf("prediction[0].PCR: got %d, want 0", policy.PCRPredictions[0].PCR)
	}
	if len(policy.PCRPredictions[0].Values) != 1 {
		t.Errorf("prediction[0].Values: got %d, want 1", len(policy.PCRPredictions[0].Values))
	}
	if policy.PCRPredictions[1].PCR != 7 {
		t.Errorf("prediction[1].PCR: got %d, want 7", policy.PCRPredictions[1].PCR)
	}
	if len(policy.PCRPredictions[1].Values) != 2 {
		t.Errorf("prediction[1].Values: got %d, want 2", len(policy.PCRPredictions[1].Values))
	}

	expectedVal0 := decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if !equalBytes(policy.PCRPredictions[0].Values[0], expectedVal0) {
		t.Errorf("prediction[0].Values[0] mismatch")
	}
}

func TestParsePCRLockJSON_DefaultBank(t *testing.T) {
	jsonData := []byte(`{
		"pcrValues": [],
		"nvIndex": 0
	}`)

	policy, err := ParsePCRLockJSON(jsonData)
	if err != nil {
		t.Fatalf("ParsePCRLockJSON: %v", err)
	}
	if policy.Bank != AlgSHA256 {
		t.Errorf("default Bank: got 0x%x, want 0x%x", policy.Bank, AlgSHA256)
	}
}

func TestParsePCRLockJSON_InvalidHex(t *testing.T) {
	jsonData := []byte(`{
		"pcrBank": "sha256",
		"nvIndex": 0,
		"pcrValues": [
			{"pcr": 0, "values": ["ZZZ"]}
		]
	}`)

	_, err := ParsePCRLockJSON(jsonData)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParsePCRLockJSON_InvalidJSON(t *testing.T) {
	_, err := ParsePCRLockJSON([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestComputePolicyPCRHash_MatchesTPMCalc(t *testing.T) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	pcrDigest := []byte{0x01, 0x02, 0x03}
	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: []byte{0x81, 0x00, 0x00},
		}},
	}

	cmd := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs:      sel,
	}
	if err := cmd.Update(calc); err != nil {
		t.Fatal(err)
	}
	expected := calc.Hash().Digest

	got, err := computePolicyPCRHash(AlgSHA256, nil, pcrDigest, sel)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyPCRHash mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyORHash_MatchesTPMCalc(t *testing.T) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	branch1 := make([]byte, 32)
	branch1[0] = 0xaa
	branch2 := make([]byte, 32)
	branch2[0] = 0xbb

	cmd := tpm2.PolicyOr{
		PHashList: tpm2.TPMLDigest{
			Digests: []tpm2.TPM2BDigest{
				{Buffer: branch1},
				{Buffer: branch2},
			},
		},
	}
	if err := cmd.Update(calc); err != nil {
		t.Fatal(err)
	}
	expected := calc.Hash().Digest

	got, err := computePolicyORHash(AlgSHA256, [][]byte{branch1, branch2})
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyORHash mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decodeHex(%q): %v", s, err)
	}
	return b
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestComputePolicyPCRHash_NonZeroStateMatchesGoTpm(t *testing.T) {
	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}
	pcrSel := buildPCRLSelection(AlgSHA256, []int{0, 7})

	step1Digest := make([]byte, 32)
	for i := range step1Digest {
		step1Digest[i] = byte(0xFF - i)
	}
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	cmd1 := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: step1Digest},
		Pcrs:      pcrSel,
	}
	if err := cmd1.Update(calc); err != nil {
		t.Fatal(err)
	}
	stateAfterStep1 := calc.Hash().Digest

	cmd2 := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs:      pcrSel,
	}
	if err := cmd2.Update(calc); err != nil {
		t.Fatal(err)
	}
	goTpmResult := calc.Hash().Digest

	manualResult, err := computePolicyPCRHash(AlgSHA256, stateAfterStep1, pcrDigest, pcrSel)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(manualResult, goTpmResult) {
		t.Errorf("non-zero state PolicyPCR mismatch:\n  manual: %x\n  go-tpm: %x", manualResult, goTpmResult)
	}
}

func TestComputePolicyPCRHash_NonZeroStateDiffersFromZeroState(t *testing.T) {
	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}
	pcrSel := buildPCRLSelection(AlgSHA256, []int{7})

	currentDigest := make([]byte, 32)
	currentDigest[0] = 0xAA

	fromZero, err := computePolicyPCRHash(AlgSHA256, nil, pcrDigest, pcrSel)
	if err != nil {
		t.Fatal(err)
	}

	fromCurrent, err := computePolicyPCRHash(AlgSHA256, currentDigest, pcrDigest, pcrSel)
	if err != nil {
		t.Fatal(err)
	}

	if equalBytes(fromZero, fromCurrent) {
		t.Error("PolicyPCR from zero vs non-zero state should produce different digests")
	}
}

func TestMarshalPCRLSelection(t *testing.T) {
	sel := buildPCRLSelection(AlgSHA256, []int{0, 7})
	marshalled := marshalPCRLSelection(sel)

	if len(marshalled) < 4+2+1+3 {
		t.Fatalf("marshalled PCR selection too short: %d bytes", len(marshalled))
	}

	count := binary.BigEndian.Uint32(marshalled[0:4])
	if count != 1 {
		t.Errorf("expected 1 selection, got %d", count)
	}

	hashAlg := binary.BigEndian.Uint16(marshalled[4:6])
	if hashAlg != 0x000B {
		t.Errorf("expected SHA256 (0x000B), got 0x%04x", hashAlg)
	}

	sizeofSelect := marshalled[6]
	if sizeofSelect != 3 {
		t.Errorf("expected sizeof_select=3, got %d", sizeofSelect)
	}

	if marshalled[7] != 0x81 {
		t.Errorf("expected bitmap byte 0 = 0x81 (PCR 0 + PCR 7), got 0x%02x", marshalled[7])
	}
}

func TestComputePolicyAuthorizeNVHash_MatchesGoTpm(t *testing.T) {
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	// PolicyAuthorizeNV.Update resets the state and extends with CC + NV Name
	nvNameBuf := make([]byte, 34)
	nvNameBuf[0] = 0x00 // nameAlg high byte
	nvNameBuf[1] = 0x0B // nameAlg low byte = SHA256
	// Remaining 32 bytes are zeros (the hash of the NV public area)
	for i := 2; i < 34; i++ {
		nvNameBuf[i] = byte(i)
	}

	nvName := tpm2.TPM2BName{Buffer: nvNameBuf}

	cmd := tpm2.PolicyAuthorizeNV{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner},
		NVIndex:       tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C20000), Name: nvName},
		PolicySession: tpm2.TPMHandle(0x03000000),
	}
	if err := cmd.Update(calculator); err != nil {
		t.Fatal(err)
	}
	expected := calculator.Hash().Digest

	got, err := computePolicyAuthorizeNVHash(nvNameBuf)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyAuthorizeNVHash mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyAuthorizeNVHash_FromNonZeroState(t *testing.T) {
	// PolicyAuthorizeNV always resets to zeros, so starting from non-zero state should produce same result
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	// First extend some state so it's non-zero
	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: []byte{0x01, 0x00, 0x00},
		}},
	}
	pcrCmd := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
		Pcrs:      pcrSel,
	}
	if err := pcrCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}

	// State should be non-zero now
	preReset := calculator.Hash().Digest
	allZeros := make([]byte, 32)
	if equalBytes(preReset, allZeros) {
		t.Fatal("expected non-zero state after PolicyPCR")
	}

	// Now apply PolicyAuthorizeNV - it resets to zeros
	nvNameBuf := make([]byte, 34)
	nvNameBuf[0] = 0x00
	nvNameBuf[1] = 0x0B
	for i := 2; i < 34; i++ {
		nvNameBuf[i] = byte(0xFF - i)
	}

	nvCmd := tpm2.PolicyAuthorizeNV{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner},
		NVIndex:       tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C20000), Name: tpm2.TPM2BName{Buffer: nvNameBuf}},
		PolicySession: tpm2.TPMHandle(0x03000000),
	}
	if err := nvCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}
	expected := calculator.Hash().Digest

	got, err := computePolicyAuthorizeNVHash(nvNameBuf)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyAuthorizeNVHash from non-zero state mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyAuthValueHash_MatchesGoTpm(t *testing.T) {
	// Test from zero state
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	cmd := tpm2.PolicyAuthValue{}
	if err := cmd.Update(calculator); err != nil {
		t.Fatal(err)
	}
	expected := calculator.Hash().Digest

	got, err := computePolicyAuthValueHash(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyAuthValueHash from zero mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyAuthValueHash_FromNonZeroState(t *testing.T) {
	// Test from non-zero state (after PolicyAuthorizeNV)
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	// First apply PolicyAuthorizeNV to get a non-zero state
	nvNameBuf := make([]byte, 34)
	nvNameBuf[0] = 0x00
	nvNameBuf[1] = 0x0B
	for i := 2; i < 34; i++ {
		nvNameBuf[i] = byte(i)
	}

	nvCmd := tpm2.PolicyAuthorizeNV{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner},
		NVIndex:       tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C20000), Name: tpm2.TPM2BName{Buffer: nvNameBuf}},
		PolicySession: tpm2.TPMHandle(0x03000000),
	}
	if err := nvCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}

	// Now apply PolicyAuthValue
	authCmd := tpm2.PolicyAuthValue{}
	if err := authCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}
	expected := calculator.Hash().Digest

	// Compute offline: first PolicyAuthorizeNV digest, then PolicyAuthValue
	authNVDigest, err := computePolicyAuthorizeNVHash(nvNameBuf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := computePolicyAuthValueHash(authNVDigest)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyAuthValueHash from PolicyAuthorizeNV state mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyAuthorizeNVThenAuthValue_FullChain(t *testing.T) {
	// Test the full chain: PolicyAuthorizeNV → PolicyAuthValue
	// This simulates the pcrlock policy: PCR policy → PolicyAuthorizeNV → PolicyAuthValue
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}

	// Apply a PCR policy first to get a realistic starting state
	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: []byte{0x81, 0x00, 0x00},
		}},
	}
	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}
	pcrCmd := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs:      pcrSel,
	}
	if err := pcrCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}

	// Apply PolicyAuthorizeNV (resets to zeros, then extends with CC + NV Name)
	nvNameBuf := make([]byte, 34)
	nvNameBuf[0] = 0x00
	nvNameBuf[1] = 0x0B
	for i := 2; i < 34; i++ {
		nvNameBuf[i] = byte(0xAA)
	}

	nvCmd := tpm2.PolicyAuthorizeNV{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner},
		NVIndex:       tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C20000), Name: tpm2.TPM2BName{Buffer: nvNameBuf}},
		PolicySession: tpm2.TPMHandle(0x03000000),
	}
	if err := nvCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}

	// Apply PolicyAuthValue
	authCmd := tpm2.PolicyAuthValue{}
	if err := authCmd.Update(calculator); err != nil {
		t.Fatal(err)
	}
	expected := calculator.Hash().Digest

	// Compute offline
	authNVDigest, err := computePolicyAuthorizeNVHash(nvNameBuf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := computePolicyAuthValueHash(authNVDigest)
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("full chain (PolicyAuthorizeNV → PolicyAuthValue) mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyAuthorizeNVWithRealNVName(t *testing.T) {
	// Validate against known values from real boot logs:
	// After PolicyAuthorizeNV, session digest = 4ba0d51a22959bf92c77fcf5cb6a5a77dad82d04132e8a965d06ec80696191ff
	// This tests that our offline computation produces the same result.
	nvName, err := hex.DecodeString("000bc0e5447b89f311b255709913b9da2860c3fe8672268ed3cb023a92210dfc1561")
	if err != nil {
		t.Fatal(err)
	}
	got, err := computePolicyAuthorizeNVHash(nvName)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := hex.DecodeString("4ba0d51a22959bf92c77fcf5cb6a5a77dad82d04132e8a965d06ec80696191ff")
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyAuthorizeNVHash with real NV Name mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}

func TestComputePolicyAuthValueFromAuthorizeNVState(t *testing.T) {
	// Validate: PolicyAuthorizeNV state → PolicyAuthValue
	// After PolicyAuthorizeNV: 4ba0d51a22959bf92c77fcf5cb6a5a77dad82d04132e8a965d06ec80696191ff
	// After PolicyAuthValue:    5bfef005d872e16ad8b72b6b59b10b4b77324bd42a2e9bb956273c3bb6fc647e
	authNVDigest, err := hex.DecodeString("4ba0d51a22959bf92c77fcf5cb6a5a77dad82d04132e8a965d06ec80696191ff")
	if err != nil {
		t.Fatal(err)
	}

	got, err := computePolicyAuthValueHash(authNVDigest)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := hex.DecodeString("5bfef005d872e16ad8b72b6b59b10b4b77324bd42a2e9bb956273c3bb6fc647e")
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(got, expected) {
		t.Errorf("computePolicyAuthValueHash from PolicyAuthorizeNV state mismatch:\n  got:    %x\n  expect: %x", got, expected)
	}
}
