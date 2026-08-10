package luks

import (
	"encoding/binary"
	"testing"
)

func TestParseNVIndexFromPublic_SpecCompliant(t *testing.T) {
	// Build a proper TPM2B_NV_PUBLIC:
	// [2 size][4 nvIndex][2 nameAlg][4 attributes][2 authPolicySize=0][2 dataSize]
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], 14)          // TPM2B size
	binary.BigEndian.PutUint32(data[2:6], 0x01800001)  // NVIndex
	binary.BigEndian.PutUint16(data[6:8], 0x000B)      // nameAlg = SHA256
	binary.BigEndian.PutUint32(data[8:12], 0x00000000) // attributes
	binary.BigEndian.PutUint16(data[12:14], 0)         // authPolicySize = 0
	binary.BigEndian.PutUint16(data[14:16], 34)        // dataSize

	got := parseNVIndexFromPublic(data)
	if got != 0x01800001 {
		t.Errorf("expected 0x01800001, got 0x%x", got)
	}
}

func TestParseNVIndexFromPublic_WithAuthPolicy(t *testing.T) {
	// Build TPM2B_NV_PUBLIC with 32-byte authPolicy:
	// [2 size][4 nvIndex][2 nameAlg][4 attributes][2 authPolicySize=32][32 authPolicy][2 dataSize]
	authPolicy := make([]byte, 32)
	for i := range authPolicy {
		authPolicy[i] = byte(i)
	}
	data := make([]byte, 14+32+2)
	binary.BigEndian.PutUint16(data[0:2], 14+32+2-2)
	binary.BigEndian.PutUint32(data[2:6], 0x01ABCDEF) // NVIndex
	binary.BigEndian.PutUint16(data[6:8], 0x000B)     // nameAlg
	binary.BigEndian.PutUint32(data[8:12], 0)         // attributes
	binary.BigEndian.PutUint16(data[12:14], 32)       // authPolicySize
	copy(data[14:46], authPolicy)
	binary.BigEndian.PutUint16(data[46:48], 34) // dataSize

	got := parseNVIndexFromPublic(data)
	if got != 0x01ABCDEF {
		t.Errorf("expected 0x01ABCDEF, got 0x%x", got)
	}
}

func TestParseNVIndexFromPublic_Offset0(t *testing.T) {
	// NV index directly at offset 0 (no TPM2B wrapping)
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], 0x018188A3)

	got := parseNVIndexFromPublic(data)
	if got != 0x018188A3 {
		t.Errorf("expected 0x018188A3, got 0x%x", got)
	}
}

func TestParseNVIndexFromPublic_TooShort(t *testing.T) {
	data := []byte{0x01, 0x80}
	got := parseNVIndexFromPublic(data)
	if got != 0 {
		t.Errorf("expected 0 for short data, got 0x%x", got)
	}
}

func TestParseNVIndexFromPublic_InvalidRange(t *testing.T) {
	// NV index outside owner hierarchy range
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], 0xDEADBEEF)

	got := parseNVIndexFromPublic(data)
	if got != 0 {
		t.Errorf("expected 0 for invalid range, got 0x%x", got)
	}
}

func TestParseNVIndexFromPublic_Empty(t *testing.T) {
	got := parseNVIndexFromPublic(nil)
	if got != 0 {
		t.Errorf("expected 0 for nil, got 0x%x", got)
	}
}

func TestIsValidNVIndex(t *testing.T) {
	tests := []struct {
		idx  uint32
		want bool
	}{
		{0x01000000, true},
		{0x01800000, true},
		{0x01BFFFFF, true},
		{0x01FFFFFF, true},
		{0x00800000, false},
		{0x02000000, false},
		{0xDEADBEEF, false},
		{0x00000000, false},
	}

	for _, tt := range tests {
		got := isValidNVIndex(tt.idx)
		if got != tt.want {
			t.Errorf("isValidNVIndex(0x%x) = %v, want %v", tt.idx, got, tt.want)
		}
	}
}

func TestParseHexUint32(t *testing.T) {
	got, err := parseHexUint32("01800001")
	if err != nil {
		t.Fatalf("parseHexUint32: %v", err)
	}
	if got != 0x01800001 {
		t.Errorf("expected 0x01800001, got 0x%x", got)
	}
}

func TestParseHexUint32TooShort(t *testing.T) {
	_, err := parseHexUint32("0100")
	if err == nil {
		t.Error("expected error for short hex string")
	}
}
