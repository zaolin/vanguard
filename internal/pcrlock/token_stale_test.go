package pcrlock

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/zaolin/vanguard/internal/tpm"
)

// buildTestESYSBlob builds a serialized ESYS_TR blob for an NV index, the
// format systemd stores in the token field tpm2_pcrlock_nv.
//
// Layout (tpm2-tss, src/tss2-esys/esys_types.h):
//
//	[0:4] handle, [4:6] name size, [6:..] name, resource type (uint32),
//	TPM2B_NV_PUBLIC
//
// The authPolicy byte selects a different index definition, which is what
// changes the NV name when the index is redefined.
func buildTestESYSBlob(index uint32, authPolicy byte) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, index)

	// TPM2B_NAME: size + algorithm + digest.
	name := make([]byte, 34)
	binary.BigEndian.PutUint16(name[0:2], 0x000B) // SHA256
	for i := 2; i < len(name); i++ {
		name[i] = authPolicy
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(name)))
	out = append(out, name...)

	// Resource type: NV.
	out = binary.BigEndian.AppendUint32(out, 2)

	// TPMS_NV_PUBLIC.
	var pub []byte
	pub = binary.BigEndian.AppendUint32(pub, index)
	pub = binary.BigEndian.AppendUint16(pub, 0x000B)     // nameAlg
	pub = binary.BigEndian.AppendUint32(pub, 0x00000002) // attributes
	pub = binary.BigEndian.AppendUint16(pub, 32)         // authPolicy size
	pub = append(pub, make([]byte, 32)...)               // authPolicy
	pub[len(pub)-1] = authPolicy                         // vary the definition
	pub = binary.BigEndian.AppendUint16(pub, 34)         // dataSize

	out = binary.BigEndian.AppendUint16(out, uint16(len(pub)))
	out = append(out, pub...)
	return out
}

func encodeTestBlob(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// The pcrlock NV index binding is identified by the serialized ESYS_TR of
// the index: the token carries it in tpm2_pcrlock_nv, the policy in
// nvHandle. The two are the same artifact, so a byte comparison decides
// whether the token still points at the index the policy describes.
func TestTokenMatchesPolicy(t *testing.T) {
	blobA := encodeTestBlob([]byte{0x01, 0x02})
	blobB := encodeTestBlob([]byte{0x01, 0x03})

	tests := []struct {
		name      string
		tokenBlob string
		polBlob   string
		wantStale bool
		wantErr   bool
	}{
		{
			name:      "identical blobs mean the token is fresh",
			tokenBlob: blobA,
			polBlob:   blobA,
			wantStale: false,
		},
		{
			name:      "a different blob means the index was redefined",
			tokenBlob: blobA,
			polBlob:   blobB,
			wantStale: true,
		},
		{
			name:      "a classic token has no NV binding and is never stale",
			tokenBlob: "",
			polBlob:   blobA,
			wantStale: false,
		},
		{
			name:      "a policy without nvHandle cannot verify the binding",
			tokenBlob: blobA,
			polBlob:   "",
			wantErr:   true,
		},
		{
			name:      "an undecodable token blob cannot verify the binding",
			tokenBlob: "!!!not-base64!!!",
			polBlob:   blobA,
			wantErr:   true,
		},
		{
			name:      "an undecodable policy blob cannot verify the binding",
			tokenBlob: blobA,
			polBlob:   "!!!not-base64!!!",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := &LUKSTPMToken{NVHandle: tc.tokenBlob, HasPCRLock: tc.tokenBlob != ""}
			policy := &Policy{NVHandle: tc.polBlob, NVIndex: 0x01919ea9}

			stale, err := TokenMatchesPolicy(token, policy)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("TokenMatchesPolicy: %v", err)
			}
			if stale != tc.wantStale {
				t.Errorf("stale = %v, want %v", stale, tc.wantStale)
			}
		})
	}
}

// TestTokenMatchesPolicyRequiresBothOperands guards the nil handling.
func TestTokenMatchesPolicyRequiresBothOperands(t *testing.T) {
	if _, err := TokenMatchesPolicy(nil, &Policy{}); err == nil {
		t.Error("nil token must be an error")
	}
	if _, err := TokenMatchesPolicy(&LUKSTPMToken{}, nil); err == nil {
		t.Error("nil policy must be an error")
	}
}

// TestParseNVIndexFromESYSBlob pins the parsing of the real systemd format:
// the token's tpm2_pcrlock_nv is a serialized ESYS_TR whose first four bytes
// are the NV index handle.
func TestParseNVIndexFromESYSBlob(t *testing.T) {
	blob := buildTestESYSBlob(0x01919ea9, 0x01)
	encoded := encodeTestBlob(blob)

	idx, err := ParseNVIndexFromBlob(encoded)
	if err != nil {
		t.Fatalf("ParseNVIndexFromBlob: %v", err)
	}
	if idx != 0x01919ea9 {
		t.Errorf("NV index = 0x%x, want 0x01919ea9", idx)
	}
}

// TestESYSBlobCarriesNVPublic pins that the public area embedded in the
// ESYS_TR blob is the one whose name the sealed blob binds — the identity
// the boot-time check verifies against the TPM's live index.
func TestESYSBlobCarriesNVPublic(t *testing.T) {
	blob := buildTestESYSBlob(0x01919ea9, 0x01)
	parsed, err := tpm.ParseESYSTrBlob(blob)
	if err != nil {
		t.Fatalf("ParseESYSTrBlob: %v", err)
	}
	if parsed.Handle != 0x01919ea9 {
		t.Errorf("handle = 0x%x, want 0x01919ea9", parsed.Handle)
	}
	if len(parsed.NVPublic) == 0 {
		t.Fatal("no NV public area in the blob")
	}
	name, err := tpm.ComputeNVNameFromPublic(parsed.NVPublic)
	if err != nil {
		t.Fatalf("ComputeNVNameFromPublic: %v", err)
	}
	if len(name) != 34 {
		t.Errorf("name length = %d, want 34", len(name))
	}
}

// TestESYSBlobNameChangesWithPublicArea pins the property the staleness
// detection relies on: redefining the index (a new public area) changes its
// name, so the token's blob and the policy's blob diverge.
func TestESYSBlobNameChangesWithPublicArea(t *testing.T) {
	a, err := tpm.ParseESYSTrBlob(buildTestESYSBlob(0x01919ea9, 0x01))
	if err != nil {
		t.Fatal(err)
	}
	b, err := tpm.ParseESYSTrBlob(buildTestESYSBlob(0x01919ea9, 0x02))
	if err != nil {
		t.Fatal(err)
	}
	nameA, err := tpm.ComputeNVNameFromPublic(a.NVPublic)
	if err != nil {
		t.Fatal(err)
	}
	nameB, err := tpm.ComputeNVNameFromPublic(b.NVPublic)
	if err != nil {
		t.Fatal(err)
	}
	if string(nameA) == string(nameB) {
		t.Error("the NV name did not change although the public area changed")
	}
}
