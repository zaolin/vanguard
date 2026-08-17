package tpm

import (
	"crypto/sha256"
	"testing"

	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

func TestExtendPCR_BasicExtend(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// Read initial PCR 11 value (should be all zeros on fresh swtpm)
	initial, err := client.ReadPCR(AlgSHA256, 11)
	if err != nil {
		t.Fatalf("ReadPCR 11 initial: %v", err)
	}
	if !isAllZeros(initial) {
		t.Errorf("PCR 11 should start as all-zeros on fresh swtpm, got: %x", initial)
	}

	// Extend PCR 11 with a test digest
	digest := sha256.Sum256([]byte("test-luks-header"))
	if err := client.ExtendPCR(11, AlgSHA256, digest[:]); err != nil {
		t.Fatalf("ExtendPCR 11: %v", err)
	}

	// Read PCR 11 after extend — should be SHA256(initial || digest)
	after, err := client.ReadPCR(AlgSHA256, 11)
	if err != nil {
		t.Fatalf("ReadPCR 11 after extend: %v", err)
	}

	// Compute expected: PCR_new = SHA256(PCR_old || digest)
	expected := sha256.Sum256(append(append([]byte{}, initial...), digest[:]...))
	if !pcrBytesEqual(after, expected[:]) {
		t.Errorf("PCR 11 after extend mismatch:\n  got:  %x\n  want: %x", after, expected[:])
	}
}

func TestExtendPCR_MultipleExtends(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	// First extend
	d1 := sha256.Sum256([]byte("first-extension"))
	if err := client.ExtendPCR(11, AlgSHA256, d1[:]); err != nil {
		t.Fatalf("ExtendPCR 11 first: %v", err)
	}
	pcrAfterFirst, err := client.ReadPCR(AlgSHA256, 11)
	if err != nil {
		t.Fatalf("ReadPCR 11 after first: %v", err)
	}

	// Second extend
	d2 := sha256.Sum256([]byte("second-extension"))
	if err := client.ExtendPCR(11, AlgSHA256, d2[:]); err != nil {
		t.Fatalf("ExtendPCR 11 second: %v", err)
	}
	pcrAfterSecond, err := client.ReadPCR(AlgSHA256, 11)
	if err != nil {
		t.Fatalf("ReadPCR 11 after second: %v", err)
	}

	// PCR should be SHA256(pcrAfterFirst || d2)
	expected := sha256.Sum256(append(append([]byte{}, pcrAfterFirst...), d2[:]...))
	if !pcrBytesEqual(pcrAfterSecond, expected[:]) {
		t.Errorf("PCR 11 after second extend mismatch:\n  got:  %x\n  want: %x", pcrAfterSecond, expected[:])
	}

	// The two PCR values should be different
	if pcrBytesEqual(pcrAfterFirst, pcrAfterSecond) {
		t.Error("PCR 11 should change after second extend")
	}
}

func TestExtendPCR_DifferentDigestsProduceDifferentValues(t *testing.T) {
	tpmTransport1, cleanup1 := swtpmtest.Setup(t)
	defer cleanup1()

	tpmTransport2, cleanup2 := swtpmtest.Setup(t)
	defer cleanup2()

	client1 := NewWithTransport(tpmTransport1)
	client2 := NewWithTransport(tpmTransport2)

	d1 := sha256.Sum256([]byte("luks-header-A"))
	d2 := sha256.Sum256([]byte("luks-header-B"))

	if err := client1.ExtendPCR(11, AlgSHA256, d1[:]); err != nil {
		t.Fatalf("ExtendPCR 11 client1: %v", err)
	}
	if err := client2.ExtendPCR(11, AlgSHA256, d2[:]); err != nil {
		t.Fatalf("ExtendPCR 11 client2: %v", err)
	}

	pcr1, _ := client1.ReadPCR(AlgSHA256, 11)
	pcr2, _ := client2.ReadPCR(AlgSHA256, 11)

	if pcrBytesEqual(pcr1, pcr2) {
		t.Error("Different digests should produce different PCR values")
	}
}

func TestExtendPCR_SameDigestProducesSameValue(t *testing.T) {
	tpmTransport1, cleanup1 := swtpmtest.Setup(t)
	defer cleanup1()

	tpmTransport2, cleanup2 := swtpmtest.Setup(t)
	defer cleanup2()

	client1 := NewWithTransport(tpmTransport1)
	client2 := NewWithTransport(tpmTransport2)

	d := sha256.Sum256([]byte("same-luks-header"))

	if err := client1.ExtendPCR(11, AlgSHA256, d[:]); err != nil {
		t.Fatalf("ExtendPCR 11 client1: %v", err)
	}
	if err := client2.ExtendPCR(11, AlgSHA256, d[:]); err != nil {
		t.Fatalf("ExtendPCR 11 client2: %v", err)
	}

	pcr1, _ := client1.ReadPCR(AlgSHA256, 11)
	pcr2, _ := client2.ReadPCR(AlgSHA256, 11)

	if !pcrBytesEqual(pcr1, pcr2) {
		t.Errorf("Same digest should produce same PCR value:\n  pcr1: %x\n  pcr2: %x", pcr1, pcr2)
	}
}

func TestExtendPCR_UnsupportedBank(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	digest := sha256.Sum256([]byte("test"))
	err := client.ExtendPCR(11, AlgSHA384, digest[:])
	if err == nil {
		t.Error("ExtendPCR with unsupported bank should fail")
	}
}

func TestExtendPCR_TamperDetection(t *testing.T) {
	// Simulate LUKS header tampering: two devices with slightly different
	// headers should produce different PCR 11 values, causing unseal failure.
	tpmTransport1, cleanup1 := swtpmtest.Setup(t)
	defer cleanup1()

	tpmTransport2, cleanup2 := swtpmtest.Setup(t)
	defer cleanup2()

	client1 := NewWithTransport(tpmTransport1)
	client2 := NewWithTransport(tpmTransport2)

	// "Original" header
	originalHeader := []byte("LUKS\xba\xbe\x00\x02" + "original-header-data")
	// "Tampered" header (one byte changed)
	tamperedHeader := []byte("LUKS\xba\xbe\x00\x02" + "tampered-header-data")

	d1 := sha256.Sum256(originalHeader)
	d2 := sha256.Sum256(tamperedHeader)

	if err := client1.ExtendPCR(11, AlgSHA256, d1[:]); err != nil {
		t.Fatalf("ExtendPCR original: %v", err)
	}
	if err := client2.ExtendPCR(11, AlgSHA256, d2[:]); err != nil {
		t.Fatalf("ExtendPCR tampered: %v", err)
	}

	pcr1, _ := client1.ReadPCR(AlgSHA256, 11)
	pcr2, _ := client2.ReadPCR(AlgSHA256, 11)

	if pcrBytesEqual(pcr1, pcr2) {
		t.Error("Tampered header should produce different PCR 11 value")
	}
}

func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func pcrBytesEqual(a, b []byte) bool {
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
