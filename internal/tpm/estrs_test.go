package tpm

import (
	"encoding/binary"
	"testing"
)

// buildESYSBlob builds a serialized ESYS_TR blob for an NV index, the format
// systemd stores in the token field tpm2_pcrlock_nv.
//
// Layout (tpm2-tss, src/tss2-esys/esys_types.h): handle, TPM2B_NAME,
// resource type, TPM2B_NV_PUBLIC.
func buildESYSBlob(index uint32, authPolicyByte byte, attrs uint32) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, index)

	name := make([]byte, 34)
	binary.BigEndian.PutUint16(name[0:2], 0x000B) // SHA256
	for i := 2; i < len(name); i++ {
		name[i] = authPolicyByte
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(name)))
	out = append(out, name...)

	out = binary.BigEndian.AppendUint32(out, iesysResourceTypeNV)

	var pub []byte
	pub = binary.BigEndian.AppendUint32(pub, index)
	pub = binary.BigEndian.AppendUint16(pub, 0x000B)
	pub = binary.BigEndian.AppendUint32(pub, attrs)
	pub = binary.BigEndian.AppendUint16(pub, 32)
	for i := 0; i < 32; i++ {
		pub = append(pub, authPolicyByte)
	}
	pub = binary.BigEndian.AppendUint16(pub, 34)

	out = binary.BigEndian.AppendUint16(out, uint16(len(pub)))
	out = append(out, pub...)
	return out
}

// TestVerifyNVIndexIdentity drives the production identity check with blobs
// and live public areas, proving both directions: a redefined index is
// rejected, and a blob the parser does not understand must not produce a
// false tamper alarm.
func TestVerifyNVIndexIdentity(t *testing.T) {
	const index = uint32(0x01919ea9)

	// A live public area with TPMA_NV_WRITTEN set, as after make-policy.
	livePublic := buildESYSBlob(index, 0x01, 1<<29)
	liveParsed, err := ParseESYSTrBlob(livePublic)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		blob    []byte
		index   uint32
		live    []byte
		wantErr bool
	}{
		{
			name:  "the same index with the Written bit set on the live side is accepted",
			blob:  buildESYSBlob(index, 0x01, 0),
			index: index,
			live:  liveParsed.NVPublic,
		},
		{
			name:    "a different authPolicy on the live index is rejected",
			blob:    buildESYSBlob(index, 0x01, 0),
			index:   index,
			live:    mustPublic(t, buildESYSBlob(index, 0x02, 0)),
			wantErr: true,
		},
		{
			name:    "a different attribute set on the live index is rejected",
			blob:    buildESYSBlob(index, 0x01, 0),
			index:   index,
			live:    mustPublic(t, buildESYSBlob(index, 0x01, 1<<3)),
			wantErr: true,
		},
		{
			name:  "a blob for another index does not cause a false alarm",
			blob:  buildESYSBlob(0x01919eaa, 0x01, 0),
			index: index,
			live:  liveParsed.NVPublic,
		},
		{
			name:  "an unparsable blob disables the check instead of alarming",
			blob:  []byte{0x01, 0x02, 0x03},
			index: index,
			live:  liveParsed.NVPublic,
		},
		{
			name:  "no blob disables the check",
			blob:  nil,
			index: index,
			live:  liveParsed.NVPublic,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyNVIndexIdentity(tc.blob, tc.index, tc.live)
			if tc.wantErr && err == nil {
				t.Error("expected a tamper error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func mustPublic(t *testing.T, blob []byte) []byte {
	t.Helper()
	parsed, err := ParseESYSTrBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.NVPublic
}

// TestParseESYSTrBlobRejectsTruncatedBlobs pins that a truncated blob can
// never yield a complete NV public area: the parser must either reject it or
// report no public area at all. Accepting a truncated area would silently
// disable the identity check while looking successful.
func TestParseESYSTrBlobRejectsTruncatedBlobs(t *testing.T) {
	blob := buildESYSBlob(0x01919ea9, 0x01, 0)
	full, err := ParseESYSTrBlob(blob)
	if err != nil {
		t.Fatalf("the valid blob was rejected: %v", err)
	}
	if len(full.NVPublic) == 0 {
		t.Fatal("the valid blob carries no NV public area")
	}

	for cut := 0; cut < len(blob); cut++ {
		parsed, err := ParseESYSTrBlob(blob[:cut])
		if err != nil {
			continue // rejected, as expected for a broken structure
		}
		if len(parsed.NVPublic) > 0 {
			t.Fatalf("a truncation to %d bytes produced a complete NV public area", cut)
		}
	}

	if _, err := ParseESYSTrBlob(nil); err == nil {
		t.Error("an empty blob must be rejected")
	}
}
