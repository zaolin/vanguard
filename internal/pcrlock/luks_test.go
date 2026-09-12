package pcrlock

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// buildNVPublicBlob builds a spec-compliant TPM2B_NV_PUBLIC blob with the
// given NV index: 2-byte size prefix + NVIndex(4) + nameAlg(2) +
// attributes(4) + authPolicySize(2) + authPolicy(0) + dataSize(2).
func buildNVPublicBlob(nvIndex uint32) []byte {
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[0:2], 12) // TPMS_NV_PUBLIC size
	binary.BigEndian.PutUint32(data[2:6], nvIndex)
	// nameAlg = SHA256 (0x000B), attributes = 0, authPolicySize = 0,
	// dataSize = 0 — payload bytes don't matter for index extraction.
	data[6] = 0x00
	data[7] = 0x0B
	return data
}

func TestExtractNVIndexFromBlob_SpecCompliant(t *testing.T) {
	// Real-world shape: TPM2B size prefix, NV index at offset 2.
	b64 := base64.StdEncoding.EncodeToString(buildNVPublicBlob(0x0193CCD1))

	idx, err := extractNVIndexFromBlob(b64)
	if err != nil {
		t.Fatalf("extractNVIndexFromBlob: %v", err)
	}
	if idx != 0x0193CCD1 {
		t.Errorf("got 0x%x, want 0x0193CCD1", idx)
	}
}

func TestExtractNVIndexFromBlob_LegacyUnwrapped(t *testing.T) {
	// Older systemd omitted the TPM2B wrapper: index at offset 0.
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 0x01800042)
	b64 := base64.StdEncoding.EncodeToString(data)

	idx, err := extractNVIndexFromBlob(b64)
	if err != nil {
		t.Fatalf("extractNVIndexFromBlob: %v", err)
	}
	if idx != 0x01800042 {
		t.Errorf("got 0x%x, want 0x01800042", idx)
	}
}

func TestExtractNVIndexFromBlob_RejectsOutOfRangeIndex(t *testing.T) {
	// A recovery NV index (0x01C30001) is NOT a pcrlock index — must be
	// rejected rather than silently accepted (cleanup depends on this).
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 0x01C30001)
	b64 := base64.StdEncoding.EncodeToString(data)

	if _, err := extractNVIndexFromBlob(b64); err == nil {
		t.Error("expected error for out-of-range NV index")
	}

	// Garbage in both strategies.
	b64 = base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01, 0x02})
	if _, err := extractNVIndexFromBlob(b64); err == nil {
		t.Error("expected error for garbage blob")
	}
}

func TestExtractNVIndexFromBlobShort(t *testing.T) {
	// Too short
	b64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	_, err := extractNVIndexFromBlob(b64)
	if err == nil {
		t.Error("expected error for too-short blob")
	}
}

func TestExtractNVIndexFromBlobInvalid(t *testing.T) {
	_, err := extractNVIndexFromBlob("!!!invalid base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestIsPcrlockNVIndex(t *testing.T) {
	valid := []uint32{0x01800000, 0x0193CCD1, 0x01BFFFFF, 0x01C20000}
	for _, idx := range valid {
		if !IsPcrlockNVIndex(idx) {
			t.Errorf("IsPcrlockNVIndex(0x%x) = false, want true", idx)
		}
	}
	invalid := []uint32{0x0, 0x01, 0x017FFFFF, 0x01C00000, 0x01C20001, 0x01C30001, 0xFFFFFFFF}
	for _, idx := range invalid {
		if IsPcrlockNVIndex(idx) {
			t.Errorf("IsPcrlockNVIndex(0x%x) = true, want false", idx)
		}
	}
}
