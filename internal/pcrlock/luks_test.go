package pcrlock

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestExtractNVIndexFromBlob(t *testing.T) {
	// Build a minimal blob: 4-byte NV index
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 0x01C30001)
	b64 := base64.StdEncoding.EncodeToString(data)

	idx, err := extractNVIndexFromBlob(b64)
	if err != nil {
		t.Fatalf("extractNVIndexFromBlob: %v", err)
	}
	if idx != 0x01C30001 {
		t.Errorf("got 0x%x, want 0x01C30001", idx)
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
