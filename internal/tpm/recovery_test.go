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

// TestStateNVLayout verifies the recovery state index byte layout:
// counter (8 bytes, uint64 BE) + fail count (4 bytes, uint32 BE) = 12 bytes.
func TestStateNVLayout(t *testing.T) {
	if CounterSize != 8 {
		t.Errorf("CounterSize: got %d, want 8", CounterSize)
	}
	if FailCountSize != 4 {
		t.Errorf("FailCountSize: got %d, want 4", FailCountSize)
	}
	if StateNVDataSize != 12 {
		t.Errorf("StateNVDataSize: got %d, want 12", StateNVDataSize)
	}

	data := make([]byte, StateNVDataSize)
	counter := uint64(0x0102030405060708)
	failCount := uint32(0xAABBCCDD)
	binary.BigEndian.PutUint64(data[0:CounterSize], counter)
	binary.BigEndian.PutUint32(data[CounterSize:StateNVDataSize], failCount)

	if got := binary.BigEndian.Uint64(data[0:CounterSize]); got != counter {
		t.Errorf("counter round-trip: got %d, want %d", got, counter)
	}
	if got := binary.BigEndian.Uint32(data[CounterSize:StateNVDataSize]); got != failCount {
		t.Errorf("fail count round-trip: got %d, want %d", got, failCount)
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

// cleanupTestNVIndexes removes the test seed and state NV indexes.
func cleanupTestNVIndexes(t *testing.T, tpmTransport transport.TPM, seedIndex uint32) {
	t.Helper()
	for _, idx := range []uint32{seedIndex, DefaultRecoveryStateNVIndex} {
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

// TestIntegration_RecoveryEnrollAndRead verifies the full cycle:
// define NV → write seed/state → read back with the same PCR values.
func TestIntegration_RecoveryEnrollAndRead(t *testing.T) {
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
		testSeed[i] = byte(i)
	}
	if err := client.WriteRecoveryData(testRecoveryNVIndex, testSeed, pcrValues); err != nil {
		t.Fatalf("WriteRecoveryData: %v", err)
	}

	seed, counter, failCount, err := client.ReadRecoveryData(testRecoveryNVIndex)
	if err != nil {
		t.Fatalf("ReadRecoveryData: %v", err)
	}
	if !bytes.Equal(seed, testSeed) {
		t.Errorf("seed mismatch:\n  got:  %x\n  want: %x", seed, testSeed)
	}
	if counter != 0 {
		t.Errorf("initial counter: got %d, want 0", counter)
	}
	if failCount != 0 {
		t.Errorf("initial fail count: got %d, want 0", failCount)
	}

	// Advance the counter and fail count; verify they persist.
	if err := client.WriteRecoveryState(42, 3); err != nil {
		t.Fatalf("WriteRecoveryState: %v", err)
	}
	counter, failCount, err = client.ReadRecoveryState()
	if err != nil {
		t.Fatalf("ReadRecoveryState: %v", err)
	}
	if counter != 42 || failCount != 3 {
		t.Errorf("state after write: counter=%d failCount=%d, want 42,3", counter, failCount)
	}
}

// TestIntegration_RecoveryStateNVDataSize verifies the state NV index size.
func TestIntegration_RecoveryStateNVDataSize(t *testing.T) {
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

	pubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DefaultRecoveryStateNVIndex)}.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVReadPublic for state: %v", err)
	}
	stPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		t.Fatalf("NVPublic.Contents for state: %v", err)
	}
	if stPub.DataSize != StateNVDataSize {
		t.Errorf("state NV data size: got %d, want %d", stPub.DataSize, StateNVDataSize)
	}
}

// TestIntegration_RecoverySeedNVDataSize verifies the seed NV index size.
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

// TestIntegration_RecoveryUndefineAndExists verifies the lifecycle.
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
	if !client.StateNVExists() {
		t.Fatal("state NV index should exist after DefineRecoveryNVSpace")
	}

	if err := client.UndefineRecoveryNVSpace(testRecoveryNVIndex, pcrValues); err != nil {
		t.Fatalf("UndefineRecoveryNVSpace: %v", err)
	}

	if client.RecoveryNVExists(testRecoveryNVIndex) {
		t.Fatal("seed NV index should not exist after UndefineRecoveryNVSpace")
	}
	if client.StateNVExists() {
		t.Fatal("state NV index should not exist after UndefineRecoveryNVSpace")
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
