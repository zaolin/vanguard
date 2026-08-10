package tpm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// --- Unit tests (no TPM required) ---

func TestComputeAllBranchDigests_Count(t *testing.T) {
	pcrValues := testPCRValues()

	digests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	if len(digests) != NumBranches {
		t.Fatalf("expected %d branch digests, got %d", NumBranches, len(digests))
	}
}

func TestComputeAllBranchDigests_EachIs32Bytes(t *testing.T) {
	pcrValues := testPCRValues()

	digests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	for i, d := range digests {
		if len(d) != 32 {
			t.Errorf("branch %d digest length: got %d, want 32", i, len(d))
		}
	}
}

func TestComputeAllBranchDigests_NonZero(t *testing.T) {
	pcrValues := testPCRValues()

	digests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	zero := make([]byte, 32)
	for i, d := range digests {
		if bytes.Equal(d, zero) {
			t.Errorf("branch %d digest is all zeros", i)
		}
	}
}

func TestComputeAllBranchDigests_Distinct(t *testing.T) {
	pcrValues := testPCRValues()

	digests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	for i := 0; i < len(digests); i++ {
		for j := i + 1; j < len(digests); j++ {
			if bytes.Equal(digests[i], digests[j]) {
				t.Errorf("branch %d and %d produce identical digests (both %x)", i, j, digests[i])
			}
		}
	}
}

func TestComputeAllBranchDigests_MatchesSeedReadPolicy(t *testing.T) {
	pcrValues := testPCRValues()

	digests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	policy, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy: %v", err)
	}

	// With single-branch policy (no PolicyOR), authPolicy = branch digest
	if !bytes.Equal(policy, digests[0]) {
		t.Errorf("computeSeedReadPolicy should equal the single branch digest:\n  policy: %x\n  branch: %x", policy, digests[0])
	}
}

func TestComputeAllBranchDigests_Deterministic(t *testing.T) {
	pcrValues := testPCRValues()

	d1, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	d2, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	for i := range d1 {
		if !bytes.Equal(d1[i], d2[i]) {
			t.Errorf("branch %d differs between calls", i)
		}
	}
}

func TestComputeAllBranchDigests_DifferentPCRsProduceDifferentDigests(t *testing.T) {
	pcrValues := testPCRValues()

	// Change PCR 7 (the only PCR in the single-branch policy)
	pcrValues2 := make(map[int][]byte)
	for k, v := range pcrValues {
		pcrValues2[k] = make([]byte, len(v))
		copy(pcrValues2[k], v)
	}
	pcrValues2[7] = bytes32(0xFF)

	d1, _ := computeAllBranchDigests(pcrValues)
	d2, _ := computeAllBranchDigests(pcrValues2)

	// Single branch (PCR 7) should differ when PCR 7 changes
	if bytes.Equal(d1[0], d2[0]) {
		t.Error("branch 0 (PCR 7) should differ when PCR 7 changes")
	}
}

func TestComputeSeedReadPolicy_DifferentPCR4DoesNotChangePolicy(t *testing.T) {
	pcrValues := testPCRValues()

	pcrValues2 := make(map[int][]byte)
	for k, v := range pcrValues {
		pcrValues2[k] = make([]byte, len(v))
		copy(pcrValues2[k], v)
	}
	pcrValues2[4] = bytes32(0xFF)

	p1, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy 1: %v", err)
	}
	p2, err := computeSeedReadPolicy(AlgSHA256, pcrValues2)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy 2: %v", err)
	}

	// With single-branch {7}, PCR 4 is not in the policy → authPolicy unchanged
	if !bytes.Equal(p1, p2) {
		t.Error("authPolicy should NOT differ when only PCR 4 changes (not in single-branch policy)")
	}
}

func TestComputeSeedReadPolicy_DifferentPCR7ChangesPolicy(t *testing.T) {
	pcrValues := testPCRValues()

	pcrValues2 := make(map[int][]byte)
	for k, v := range pcrValues {
		pcrValues2[k] = make([]byte, len(v))
		copy(pcrValues2[k], v)
	}
	pcrValues2[7] = bytes32(0xFF)

	p1, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy 1: %v", err)
	}
	p2, err := computeSeedReadPolicy(AlgSHA256, pcrValues2)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy 2: %v", err)
	}

	if bytes.Equal(p1, p2) {
		t.Error("authPolicy should differ when PCR 7 changes (all branches depend on PCR 7)")
	}
}

func TestComputeSeedReadPolicy_MissingPCR7(t *testing.T) {
	pcrValues := map[int][]byte{
		0: bytes32(0xAA),
		4: bytes32(0xBB),
		// PCR 7 missing — required by the single-branch policy
	}

	_, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err == nil {
		t.Error("expected error for missing PCR 7")
	}
}

func TestSeedReadPolicyPCRs_BranchCount(t *testing.T) {
	if len(SeedReadPolicyPCRs) != NumBranches {
		t.Errorf("SeedReadPolicyPCRs has %d branches, expected %d", len(SeedReadPolicyPCRs), NumBranches)
	}
}

func TestSeedReadPolicyPCRs_BranchContents(t *testing.T) {
	expected := [][]int{
		{7}, // Single branch: Secure Boot state
	}

	for i, want := range expected {
		if len(SeedReadPolicyPCRs[i]) != len(want) {
			t.Errorf("branch %d length: got %v, want %v", i, SeedReadPolicyPCRs[i], want)
			continue
		}
		for j, pcr := range want {
			if SeedReadPolicyPCRs[i][j] != pcr {
				t.Errorf("branch %d PCR %d: got %d, want %d", i, j, SeedReadPolicyPCRs[i][j], pcr)
			}
		}
	}
}

func TestTimestampNVDataSize(t *testing.T) {
	expected := TimestampSize + NumBranches*BranchDigestSize // 8 + 1*32 = 40
	if TimestampNVDataSize != expected {
		t.Errorf("TimestampNVDataSize: got %d, want %d", TimestampNVDataSize, expected)
	}
}

func TestTimestampNVDataSize_Layout(t *testing.T) {
	if TimestampSize != 8 {
		t.Errorf("TimestampSize: got %d, want 8", TimestampSize)
	}
	if BranchDigestSize != 32 {
		t.Errorf("BranchDigestSize: got %d, want 32", BranchDigestSize)
	}
	if NumBranches != 1 {
		t.Errorf("NumBranches: got %d, want 1", NumBranches)
	}
}

// TestBranchDigestSerialization_Layout verifies the byte layout of the
// timestamp NV index: 8 bytes timestamp + 1×32 bytes branch digest.
func TestBranchDigestSerialization_Layout(t *testing.T) {
	pcrValues := testPCRValues()
	branchDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	tsData := make([]byte, TimestampNVDataSize)
	testTimestamp := int64(1234567890)
	binary.BigEndian.PutUint64(tsData, uint64(testTimestamp))
	for i, bd := range branchDigests {
		copy(tsData[TimestampSize+i*BranchDigestSize:], bd)
	}

	if len(tsData) != 40 {
		t.Fatalf("tsData length: got %d, want 40", len(tsData))
	}

	// Verify timestamp
	readTimestamp := int64(binary.BigEndian.Uint64(tsData[0:TimestampSize]))
	if readTimestamp != testTimestamp {
		t.Errorf("timestamp: got %d, want %d", readTimestamp, testTimestamp)
	}

	// Verify branch digest (single branch)
	for i, bd := range branchDigests {
		start := TimestampSize + i*BranchDigestSize
		end := start + BranchDigestSize
		got := tsData[start:end]
		if !bytes.Equal(got, bd) {
			t.Errorf("branch %d digest mismatch:\n  got:  %x\n  want: %x", i, got, bd)
		}
	}
}

// TestBranchDigestSerialization_RoundTrip verifies that branch digests
// can be packed and unpacked identically.
func TestBranchDigestSerialization_RoundTrip(t *testing.T) {
	pcrValues := testPCRValues()
	original, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	// Pack
	tsData := make([]byte, TimestampNVDataSize)
	for i, bd := range original {
		copy(tsData[TimestampSize+i*BranchDigestSize:], bd)
	}

	// Unpack
	unpacked := make([][]byte, 0, NumBranches)
	for i := 0; i < NumBranches; i++ {
		start := TimestampSize + i*BranchDigestSize
		end := start + BranchDigestSize
		bd := make([]byte, BranchDigestSize)
		copy(bd, tsData[start:end])
		unpacked = append(unpacked, bd)
	}

	for i := range original {
		if !bytes.Equal(original[i], unpacked[i]) {
			t.Errorf("branch %d round-trip mismatch:\n  orig: %x\n  got:  %x", i, original[i], unpacked[i])
		}
	}
}

func TestConvertToTPM2BDigests(t *testing.T) {
	digests := [][]byte{
		decodeHex(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
		decodeHex(t, "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00"),
	}

	result := convertToTPM2BDigests(digests)
	if len(result) != len(digests) {
		t.Fatalf("length: got %d, want %d", len(result), len(digests))
	}

	for i, d := range digests {
		if !bytes.Equal(result[i].Buffer, d) {
			t.Errorf("digest %d mismatch", i)
		}
	}
}

func TestConvertToTPM2BDigests_Empty(t *testing.T) {
	result := convertToTPM2BDigests(nil)
	if len(result) != 0 {
		t.Errorf("empty input: got %d, want 0", len(result))
	}
}

// --- PolicyOR semantics tests ---

// TestPolicyORWithEnrollmentDigests_SamePCRs verifies that when current
// PCRs match enrollment PCRs, PolicyOR with enrollment digests produces
// the same result as PolicyOR with current digests.
func TestPolicyORWithEnrollmentDigests_SamePCRs(t *testing.T) {
	pcrValues := testPCRValues()

	enrollmentDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	currentDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	enrollmentOR, err := computePolicyORHash(AlgSHA256, enrollmentDigests)
	if err != nil {
		t.Fatalf("computePolicyORHash (enrollment): %v", err)
	}

	currentOR, err := computePolicyORHash(AlgSHA256, currentDigests)
	if err != nil {
		t.Fatalf("computePolicyORHash (current): %v", err)
	}

	if !bytes.Equal(enrollmentOR, currentOR) {
		t.Error("when PCRs are the same, enrollment and current PolicyOR digests should match")
	}
}

// TestPolicyORWithEnrollmentDigests_DifferentPCR4 verifies that when PCR 4
// changes (kernel update), the single PCR 7 branch is unaffected — the
// authPolicy (PolicyPCR digest) is the same because it only depends on PCR 7.
func TestPolicyORWithEnrollmentDigests_DifferentPCR4(t *testing.T) {
	enrollmentPCR := testPCRValues()

	// Simulate PCR 4 change at boot — should NOT affect the PCR 7 branch
	bootPCR := make(map[int][]byte)
	for k, v := range enrollmentPCR {
		bootPCR[k] = make([]byte, len(v))
		copy(bootPCR[k], v)
	}
	bootPCR[4] = bytes32(0xFF)

	// authPolicy is now just PolicyPCR(PCR 7) — no PolicyOR
	enrollmentPolicy, err := computeSeedReadPolicy(AlgSHA256, enrollmentPCR)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy (enrollment): %v", err)
	}

	bootPolicy, err := computeSeedReadPolicy(AlgSHA256, bootPCR)
	if err != nil {
		t.Fatalf("computeSeedReadPolicy (boot): %v", err)
	}

	// With single-branch {7}, PCR 4 change doesn't affect the authPolicy
	if !bytes.Equal(enrollmentPolicy, bootPolicy) {
		t.Error("authPolicy (PolicyPCR for PCR 7) should be identical when only PCR 4 changes")
	}
}

// TestPolicyORWithEnrollmentDigests_DifferentPCR7 verifies that when PCR 7
// changes (Secure Boot state changed), the branch digest changes — the seed
// becomes inaccessible. This is correct: a Secure Boot change means the
// seed should be inaccessible (anti-evil-maid).
func TestPolicyORWithEnrollmentDigests_DifferentPCR7(t *testing.T) {
	enrollmentPCR := testPCRValues()

	bootPCR := make(map[int][]byte)
	for k, v := range enrollmentPCR {
		bootPCR[k] = make([]byte, len(v))
		copy(bootPCR[k], v)
	}
	bootPCR[7] = bytes32(0xFF)

	enrollmentDigests, err := computeAllBranchDigests(enrollmentPCR)
	if err != nil {
		t.Fatalf("computeAllBranchDigests (enrollment): %v", err)
	}

	bootDigests, _ := computeAllBranchDigests(bootPCR)

	// The single branch (PCR 7) should differ when PCR 7 changes
	if bytes.Equal(enrollmentDigests[0], bootDigests[0]) {
		t.Error("branch 0 (PCR 7) should differ when PCR 7 changes — seed must become inaccessible")
	}
}

// --- Integration tests (require TPM) ---

// skipIfNoTPMForRecovery opens the TPM for integration tests, skipping if unavailable.
func skipIfNoTPMForRecovery(t *testing.T) transport.TPMCloser {
	t.Helper()
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		tpm, err = linuxtpm.Open("/dev/tpm0")
	}
	if err != nil {
		t.Skip("No TPM device available")
	}
	return tpm
}

// testRecoveryNVIndex is a non-default NV index used for integration tests
// to avoid colliding with any existing recovery setup.
const testRecoveryNVIndex = 0x01C30010

// cleanupTestNVIndexes removes the test seed and timestamp NV indexes.
func cleanupTestNVIndexes(t *testing.T, tpmTransport transport.TPM, seedIndex uint32) {
	t.Helper()
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)

	// Use test-specific indexes to avoid collision with real recovery data
	testSeedIdx := seedIndex
	testTsIdx := tsIndex

	for _, idx := range []uint32{testSeedIdx, testTsIdx} {
		pubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(idx)}.Execute(tpmTransport)
		if err != nil {
			continue // doesn't exist
		}
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(idx), Name: pubRsp.NVName},
		}.Execute(tpmTransport)
	}
}

// TestIntegration_RecoveryEnrollAndRead_SamePCRs verifies the full cycle:
// define NV → write seed → read seed back with the same PCR values.
func TestIntegration_RecoveryEnrollAndRead_SamePCRs(t *testing.T) {
	tpmTransport := skipIfNoTPMForRecovery(t)
	defer tpmTransport.Close()

	t.Cleanup(func() { cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex) })
	cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex)

	client := New()

	// Read current PCR values
	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		val, err := client.ReadPCR(AlgSHA256, pcr)
		if err != nil {
			t.Fatalf("ReadPCR %d: %v", pcr, err)
		}
		pcrValues[pcr] = val
	}

	// Define NV space
	if err := client.DefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	// Write recovery data
	testSeed := make([]byte, SeedSize)
	for i := range testSeed {
		testSeed[i] = byte(i)
	}
	testTimestamp := int64(1234567890)
	if err := client.WriteRecoveryData(testRecoveryNVIndex, testSeed, testTimestamp, pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Read recovery data back
	seed, refTimestamp, branchDigests, err := client.ReadRecoveryData(testRecoveryNVIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData: %v", err)
	}

	if !bytes.Equal(seed, testSeed) {
		t.Errorf("seed mismatch:\n  got:  %x\n  want: %x", seed, testSeed)
	}
	if refTimestamp != testTimestamp {
		t.Errorf("timestamp: got %d, want %d", refTimestamp, testTimestamp)
	}
	if len(branchDigests) != NumBranches {
		t.Fatalf("branch digests: got %d, want %d", len(branchDigests), NumBranches)
	}

	// Verify branch digests match what we'd compute from current PCRs
	expectedDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}
	for i := range branchDigests {
		if !bytes.Equal(branchDigests[i], expectedDigests[i]) {
			t.Errorf("branch %d digest mismatch:\n  got:  %x\n  want: %x", i, branchDigests[i], expectedDigests[i])
		}
	}
}

// TestIntegration_RecoveryReadBranchDigestsStored verifies that the branch
// digests stored in the timestamp NV index match the enrollment-time digests.
func TestIntegration_RecoveryReadBranchDigestsStored(t *testing.T) {
	tpmTransport := skipIfNoTPMForRecovery(t)
	defer tpmTransport.Close()

	t.Cleanup(func() { cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex) })
	cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex)

	client := New()

	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		val, err := client.ReadPCR(AlgSHA256, pcr)
		if err != nil {
			t.Fatalf("ReadPCR %d: %v", pcr, err)
		}
		pcrValues[pcr] = val
	}

	if err := client.DefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	testSeed := make([]byte, SeedSize)
	for i := range testSeed {
		testSeed[i] = byte(i + 1)
	}
	if err := client.WriteRecoveryData(testRecoveryNVIndex, testSeed, 42, pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	_, _, branchDigests, err := client.ReadRecoveryData(testRecoveryNVIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData: %v", err)
	}

	// The stored digests should match what computeAllBranchDigests produces
	expected, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		t.Fatalf("computeAllBranchDigests: %v", err)
	}

	for i := range expected {
		if !bytes.Equal(branchDigests[i], expected[i]) {
			t.Errorf("stored branch %d digest mismatch:\n  stored: %x\n  expect: %x", i, branchDigests[i], expected[i])
		}
	}
}

// TestIntegration_RecoveryTimestampUpdatePreservesDigests verifies that
// UpdateRecoveryTimestamp does not corrupt the stored branch digests.
func TestIntegration_RecoveryTimestampUpdatePreservesDigests(t *testing.T) {
	tpmTransport := skipIfNoTPMForRecovery(t)
	defer tpmTransport.Close()

	t.Cleanup(func() { cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex) })
	cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex)

	client := New()

	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		val, err := client.ReadPCR(AlgSHA256, pcr)
		if err != nil {
			t.Fatalf("ReadPCR %d: %v", pcr, err)
		}
		pcrValues[pcr] = val
	}

	if err := client.DefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	testSeed := make([]byte, SeedSize)
	for i := range testSeed {
		testSeed[i] = byte(0xAB)
	}
	originalTs := int64(1000000)
	if err := client.WriteRecoveryData(testRecoveryNVIndex, testSeed, originalTs, pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	// Read original branch digests
	_, _, origDigests, err := client.ReadRecoveryData(testRecoveryNVIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData (original): %v", err)
	}

	// Update timestamp
	newTs := int64(9999999)
	if err := client.UpdateRecoveryTimestamp(newTs); err != nil {
		t.Fatalf("UpdateRecoveryTimestamp: %v", err)
	}

	// Read again — timestamp should change but branch digests should be preserved
	_, readTs, newDigests, err := client.ReadRecoveryData(testRecoveryNVIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData (after update): %v", err)
	}

	if readTs != newTs {
		t.Errorf("timestamp after update: got %d, want %d", readTs, newTs)
	}

	for i := range origDigests {
		if !bytes.Equal(origDigests[i], newDigests[i]) {
			t.Errorf("branch %d digest changed after timestamp update:\n  before: %x\n  after:  %x", i, origDigests[i], newDigests[i])
		}
	}
}

// TestIntegration_RecoveryNVDataSize verifies the timestamp NV index has
// the expected data size (104 bytes) after definition.
func TestIntegration_RecoveryNVDataSize(t *testing.T) {
	tpmTransport := skipIfNoTPMForRecovery(t)
	defer tpmTransport.Close()

	t.Cleanup(func() { cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex) })
	cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex)

	client := New()

	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		val, err := client.ReadPCR(AlgSHA256, pcr)
		if err != nil {
			t.Fatalf("ReadPCR %d: %v", pcr, err)
		}
		pcrValues[pcr] = val
	}

	if err := client.DefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	// Check timestamp NV index data size
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	pubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tsIndex)}.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVReadPublic for timestamp: %v", err)
	}

	tsPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		t.Fatalf("NVPublic.Contents for timestamp: %v", err)
	}

	if tsPub.DataSize != TimestampNVDataSize {
		t.Errorf("timestamp NV data size: got %d, want %d", tsPub.DataSize, TimestampNVDataSize)
	}
}

// TestIntegration_RecoverySeedNVDataSize verifies the seed NV index has
// the expected data size (32 bytes).
func TestIntegration_RecoverySeedNVDataSize(t *testing.T) {
	tpmTransport := skipIfNoTPMForRecovery(t)
	defer tpmTransport.Close()

	t.Cleanup(func() { cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex) })
	cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex)

	client := New()

	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		val, err := client.ReadPCR(AlgSHA256, pcr)
		if err != nil {
			t.Fatalf("ReadPCR %d: %v", pcr, err)
		}
		pcrValues[pcr] = val
	}

	if err := client.DefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	pubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(testRecoveryNVIndex)}.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVReadPublic for seed: %v", err)
	}

	seedPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		t.Fatalf("NVPublic.Contents for seed: %v", err)
	}

	if seedPub.DataSize != SeedSize {
		t.Errorf("seed NV data size: got %d, want %d", seedPub.DataSize, SeedSize)
	}
}

// TestIntegration_RecoveryUndefineAndExists verifies the lifecycle:
// define → exists → undefine → not exists.
func TestIntegration_RecoveryUndefineAndExists(t *testing.T) {
	tpmTransport := skipIfNoTPMForRecovery(t)
	defer tpmTransport.Close()

	t.Cleanup(func() { cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex) })
	cleanupTestNVIndexes(t, tpmTransport, testRecoveryNVIndex)

	client := New()

	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		val, err := client.ReadPCR(AlgSHA256, pcr)
		if err != nil {
			t.Fatalf("ReadPCR %d: %v", pcr, err)
		}
		pcrValues[pcr] = val
	}

	if client.RecoveryNVExists(testRecoveryNVIndex) {
		t.Fatal("seed NV index should not exist before DefineRecoveryNVSpace")
	}

	if err := client.DefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("DefineRecoveryNVSpace: %v", err)
	}

	if !client.RecoveryNVExists(testRecoveryNVIndex) {
		t.Fatal("seed NV index should exist after DefineRecoveryNVSpace")
	}

	if err := client.UndefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("UndefineRecoveryNVSpace: %v", err)
	}

	if client.RecoveryNVExists(testRecoveryNVIndex) {
		t.Fatal("seed NV index should not exist after UndefineRecoveryNVSpace")
	}
}

// --- Helpers ---

func testPCRValues() map[int][]byte {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic("invalid hex in testPCRValues: " + err.Error())
		}
		return b
	}
	return map[int][]byte{
		0: mustHex("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
		4: mustHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		7: mustHex("11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00"),
	}
}
