package tpm

import (
	"encoding/binary"
	"errors"
	"testing"
)

// fakeRandomTransport returns a canned GetRandom response with a fixed number
// of bytes per call, so short-read behavior can be tested without a TPM.
type fakeRandomTransport struct {
	perCall int
	fill    byte
}

func (f *fakeRandomTransport) Send([]byte) ([]byte, error) {
	data := make([]byte, f.perCall)
	for i := range data {
		data[i] = f.fill
	}
	// A no-session response carries NO parameterSize field (verified against
	// a real swtpm GetRandom response): tag, size, rc, then TPM2B size + data.
	out := make([]byte, 12+len(data))
	binary.BigEndian.PutUint16(out[0:2], 0x8001)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(out)))
	binary.BigEndian.PutUint32(out[6:10], 0)
	binary.BigEndian.PutUint16(out[10:12], uint16(len(data)))
	copy(out[12:], data)
	return out, nil
}

func (f *fakeRandomTransport) Close() error { return nil }

// TestGetRandomSmokeShortReadsAreInconclusive pins that a short response does
// NOT produce ErrRandomIdentical: a healthy TPM returning few bytes must not
// look like a broken RNG.
func TestGetRandomSmokeShortReadsAreInconclusive(t *testing.T) {
	client := NewWithTransport(&fakeRandomTransport{perCall: 1, fill: 0xAA})

	err := client.GetRandomSmoke()
	if err == nil {
		t.Fatal("expected an inconclusive result when too few bytes arrive")
	}
	if errors.Is(err, ErrRandomIdentical) {
		t.Errorf("a short read was misclassified as a broken RNG: %v", err)
	}
}

// TestGetRandomSmokeAccumulatesBeforeComparing pins that the reads are
// accumulated to 32 bytes before the comparison: a deterministic RNG is then
// correctly reported as broken.
func TestGetRandomSmokeAccumulatesBeforeComparing(t *testing.T) {
	client := NewWithTransport(&fakeRandomTransport{perCall: 16, fill: 0xAA})

	err := client.GetRandomSmoke()
	if !errors.Is(err, ErrRandomIdentical) {
		t.Errorf("a deterministic RNG was not detected: %v", err)
	}
}
