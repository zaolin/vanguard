package luks

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

// b64Blob encodes raw bytes as base64 for the shared blob parser.
func b64Blob(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func TestParseNVIndexFromBlob_SpecCompliant(t *testing.T) {
	// Build a proper TPM2B_NV_PUBLIC:
	// [2 size][4 nvIndex][2 nameAlg][4 attributes][2 authPolicySize=0][2 dataSize]
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], 14)          // TPM2B size
	binary.BigEndian.PutUint32(data[2:6], 0x01800001)  // NVIndex
	binary.BigEndian.PutUint16(data[6:8], 0x000B)      // nameAlg = SHA256
	binary.BigEndian.PutUint32(data[8:12], 0x00000000) // attributes
	binary.BigEndian.PutUint16(data[12:14], 0)         // authPolicySize = 0
	binary.BigEndian.PutUint16(data[14:16], 34)        // dataSize

	got, err := pcrlock.ParseNVIndexFromBlob(b64Blob(data))
	if err != nil {
		t.Fatalf("ParseNVIndexFromBlob: %v", err)
	}
	if got != 0x01800001 {
		t.Errorf("expected 0x01800001, got 0x%x", got)
	}
}

func TestParseNVIndexFromBlob_WithAuthPolicy(t *testing.T) {
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

	got, err := pcrlock.ParseNVIndexFromBlob(b64Blob(data))
	if err != nil {
		t.Fatalf("ParseNVIndexFromBlob: %v", err)
	}
	if got != 0x01ABCDEF {
		t.Errorf("expected 0x01ABCDEF, got 0x%x", got)
	}
}

func TestParseNVIndexFromBlob_Offset0(t *testing.T) {
	// NV index directly at offset 0 (no TPM2B wrapping)
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], 0x018188A3)

	got, err := pcrlock.ParseNVIndexFromBlob(b64Blob(data))
	if err != nil {
		t.Fatalf("ParseNVIndexFromBlob: %v", err)
	}
	if got != 0x018188A3 {
		t.Errorf("expected 0x018188A3, got 0x%x", got)
	}
}

func TestParseNVIndexFromBlob_TooShort(t *testing.T) {
	data := []byte{0x01, 0x80}
	if _, err := pcrlock.ParseNVIndexFromBlob(b64Blob(data)); err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseNVIndexFromBlob_InvalidRange(t *testing.T) {
	// NV index outside pcrlock range
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], 0xDEADBEEF)

	if _, err := pcrlock.ParseNVIndexFromBlob(b64Blob(data)); err == nil {
		t.Error("expected error for invalid range")
	}
}

func TestParseNVIndexFromBlob_Empty(t *testing.T) {
	if _, err := pcrlock.ParseNVIndexFromBlob(b64Blob(nil)); err == nil {
		t.Error("expected error for nil data")
	}
}

func TestIsPcrlockNVIndex_SharedValidator(t *testing.T) {
	// The shared validator is stricter than the old isValidNVIndex: only the
	// pcrlock owner range (0x01800000–0x01BFFFFF) and the legacy default
	// (0x01C20000) count. This excludes vanguard's own recovery indexes.
	valid := []uint32{0x01800000, 0x01BFFFFF, 0x01C20000}
	for _, idx := range valid {
		if !pcrlock.IsPcrlockNVIndex(idx) {
			t.Errorf("IsPcrlockNVIndex(0x%x) = false, want true", idx)
		}
	}
	invalid := []uint32{0x01000000, 0x017FFFFF, 0x01C00000, 0x01C30001, 0x01FFFFFF, 0xDEADBEEF, 0x00000000}
	for _, idx := range invalid {
		if pcrlock.IsPcrlockNVIndex(idx) {
			t.Errorf("IsPcrlockNVIndex(0x%x) = true, want false", idx)
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
