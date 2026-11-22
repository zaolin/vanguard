package tpm

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestMaskedNVNameMatchesDefinitionAndSurvivesWrite pins the property the
// boot-time NV identity check depends on.
//
// The token carries the NV index's public area as it was when the index was
// defined; the TPM's live public area differs from it in the volatile
// attribute bits — TPMA_NV_WRITTEN is set by the first write. The identity
// check therefore compares names computed over the MASKED public areas, and
// this test proves on a real TPM (swtpm) that those names agree before and
// after a write, while the TPM's own name is free to change.
func TestMaskedNVNameMatchesDefinitionAndSurvivesWrite(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	const index = uint32(0x01919EA9)

	definition := tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			NT:         tpm2.TPMNTOrdinary,
			WriteAll:   true,
		},
		DataSize: 34,
	}

	// Undefine a leftover index from an earlier run, then define fresh.
	_, _ = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
	}.Execute(tpmTransport)

	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		PublicInfo: tpm2.New2B(definition),
	}).Execute(tpmTransport); err != nil {
		t.Fatalf("NVDefineSpace: %v", err)
	}
	defer func() {
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
	}()

	// The name of the index as it was defined — this is what the token's
	// blob records.
	definitionBlob := tpm2.New2B(definition)
	definitionBytes := definitionBlob.Bytes()
	definitionName, err := ComputeNVNameFromPublic(definitionBytes)
	if err != nil {
		t.Fatalf("ComputeNVNameFromPublic(definition): %v", err)
	}

	readLive := func() (masked []byte, raw []byte) {
		rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tpmTransport)
		if err != nil {
			t.Fatalf("NVReadPublic: %v", err)
		}
		name, err := ComputeNVNameFromPublic(rsp.NVPublic.Bytes())
		if err != nil {
			t.Fatalf("ComputeNVNameFromPublic(live): %v", err)
		}
		return name, rsp.NVName.Buffer
	}

	beforeMasked, beforeRaw := readLive()
	if !bytes.Equal(beforeMasked, definitionName) {
		t.Errorf("the live masked name does not match the definition-time name:\n  definition: %x\n  live:       %x", definitionName, beforeMasked)
	}

	// Write to the index: this sets TPMA_NV_WRITTEN.
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: make([]byte, 34)},
	}).Execute(tpmTransport); err != nil {
		t.Fatalf("NVWrite: %v", err)
	}

	afterMasked, afterRaw := readLive()
	if !bytes.Equal(afterMasked, definitionName) {
		t.Errorf("the masked name changed after the first write — the boot-time identity check would report a false tamper:\n  definition: %x\n  live:       %x", definitionName, afterMasked)
	}
	if bytes.Equal(beforeRaw, afterRaw) {
		t.Log("the TPM's own name did not change on write; the masking is a no-op on this TPM")
	} else {
		t.Logf("the TPM's own name changed on write (%x -> %x) while the masked name stayed stable — masking is required", beforeRaw, afterRaw)
	}
}

// TestVerifyNVIndexIdentityAgainstRealIndex drives the production identity
// check against a real NV index lifecycle on swtpm instead of synthetic
// bytes: the token blob is built from the index's actual public area and name
// as the TPM reports them, the check passes, and after the index is undefined
// and defined anew the check rejects it.
func TestVerifyNVIndexIdentityAgainstRealIndex(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	const index = uint32(0x01919EA9)

	undefine := func() {
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
	}
	define := func(dataSize uint16) {
		undefine()
		if _, err := (tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
				NVIndex: tpm2.TPMHandle(index),
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					NT:         tpm2.TPMNTOrdinary,
					WriteAll:   true,
				},
				DataSize: dataSize,
			}),
		}).Execute(tpmTransport); err != nil {
			t.Fatalf("NVDefineSpace: %v", err)
		}
	}
	readLive := func() *tpm2.NVReadPublicResponse {
		rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tpmTransport)
		if err != nil {
			t.Fatalf("NVReadPublic: %v", err)
		}
		return rsp
	}

	define(34)
	defer undefine()
	live := readLive()

	// The token's ESYS_TR blob, assembled from the real index data in the
	// tpm2-tss layout: handle, TPM2B_NAME, resource type, TPM2B_NV_PUBLIC.
	blob := buildESYSBlobFromLive(index, live)

	if err := verifyNVIndexIdentity(blob, index, live.NVPublic.Bytes()); err != nil {
		t.Fatalf("the identity check rejected the index it was built from: %v", err)
	}

	// Redefining the index changes its public area and must be detected.
	define(64)
	liveAfter := readLive()
	if err := verifyNVIndexIdentity(blob, index, liveAfter.NVPublic.Bytes()); err == nil {
		t.Error("the identity check accepted a redefined index")
	}
}

// buildESYSBlobFromLive assembles an ESYS_TR blob from a real NVReadPublic
// response, in the layout tpm2-tss serializes it.
func buildESYSBlobFromLive(index uint32, rsp *tpm2.NVReadPublicResponse) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, index)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rsp.NVName.Buffer)))
	out = append(out, rsp.NVName.Buffer...)
	out = binary.BigEndian.AppendUint32(out, iesysResourceTypeNV)
	public := rsp.NVPublic.Bytes()
	out = binary.BigEndian.AppendUint16(out, uint16(len(public)))
	out = append(out, public...)
	return out
}

// TestMaskedNVNameChangesOnRedefinition pins the other direction: an index
// that is undefined and defined anew with different parameters gets a
// different masked name, which is what makes a token stale.
func TestMaskedNVNameChangesOnRedefinition(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	const index = uint32(0x01919EA9)
	define := func(dataSize uint16) []byte {
		def := tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(index),
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				NT:         tpm2.TPMNTOrdinary,
				WriteAll:   true,
			},
			DataSize: dataSize,
		}
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
		if _, err := (tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			PublicInfo: tpm2.New2B(def),
		}).Execute(tpmTransport); err != nil {
			t.Fatalf("NVDefineSpace: %v", err)
		}
		defBlob := tpm2.New2B(def)
		name, err := ComputeNVNameFromPublic(defBlob.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return name
	}

	first := define(34)
	second := define(64)
	defer func() {
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
	}()

	if bytes.Equal(first, second) {
		t.Error("the masked name did not change although the index was redefined with a different size")
	}
}
