package tpm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/zaolin/vanguard/init/buildtags"
)

// iesysResourceTypeNV is the ESYS resource type tag for NV RAM objects
// (tpm2-tss, src/tss2-esys/esys_types.h: IESYSC_NV_RSRC).
const iesysResourceTypeNV = 2

// ESYSTrBlob holds the parts of a serialized ESYS_TR blob that identify a
// TPM object.
//
// The layout is the marshalling of IESYS_RESOURCE (tpm2-tss,
// src/tss2-esys/esys_types.h), in struct order:
//
//	[0:4]            handle (TPM2_HANDLE)
//	[4:6]            name size (uint16)
//	[6:6+nameSize]   name (TPM2B_NAME body: algorithm (2) + digest)
//	[..:..]          resource type (uint32)
//	[..:..]          resource specific data (TPM2B_NV_PUBLIC for NV)
//
// systemd stores the serialized ESYS_TR of the pcrlock NV index in the
// LUKS token field "tpm2_pcrlock_nv" and in the policy file field
// "nvHandle". Both are the same artifact, which is how systemd itself
// matches a token to its policy (tpm2_pcrlock_policy_from_credentials).
type ESYSTrBlob struct {
	// Handle is the TPM handle of the object. For an NV index it is the
	// index value itself (0x01800000-0x01FFFFFF for the pcrlock range).
	Handle uint32
	// Name is the TPM name of the object as recorded when the ESYS_TR
	// was created. For an NV index this is the name of the index's
	// public area in its "as defined" state (TPMA_NV_WRITTEN clear).
	Name []byte
	// NVPublic is the TPMS_NV_PUBLIC of an NV resource (without the
	// TPM2B size prefix), nil for other resource types.
	NVPublic []byte
}

// ParseESYSTrBlob parses a serialized ESYS_TR blob.
//
// A blob that does not follow the layout above is rejected: the caller
// must not silently treat unparsable data as a verified identity.
func ParseESYSTrBlob(data []byte) (*ESYSTrBlob, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("ESYS_TR blob too short: %d bytes", len(data))
	}

	blob := &ESYSTrBlob{Handle: binary.BigEndian.Uint32(data[0:4])}

	nameSize := int(binary.BigEndian.Uint16(data[4:6]))
	off := 6
	if nameSize < 2 || off+nameSize > len(data) {
		return nil, fmt.Errorf("ESYS_TR blob: invalid name size %d", nameSize)
	}
	blob.Name = data[off : off+nameSize]
	off += nameSize

	if off+4 > len(data) {
		return nil, fmt.Errorf("ESYS_TR blob: truncated resource type")
	}
	resourceType := binary.BigEndian.Uint32(data[off : off+4])
	off += 4

	if resourceType == iesysResourceTypeNV {
		if off+2 > len(data) {
			return nil, fmt.Errorf("ESYS_TR blob: truncated NV public area")
		}
		size := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if size == 0 || off+size > len(data) {
			return nil, fmt.Errorf("ESYS_TR blob: invalid NV public area size %d", size)
		}
		blob.NVPublic = data[off : off+size]
	}

	return blob, nil
}

// verifyNVIndexIdentity checks that the NV index currently in the TPM is the
// index the token was sealed against.
//
// The token carries the serialized ESYS_TR of the pcrlock NV index. That blob
// embeds the index's public area as it was when the index was defined; the
// TPM's live public area differs from it only in the volatile attribute bits
// (TPMA_NV_WRITTEN is set once the index has been written). Both sides are
// therefore compared by the name computed over the masked attributes.
//
// This catches NV index redefinition (an attacker undefines the real index
// and defines a rogue one with the same handle) and spoofing (same
// attributes, different authPolicy).
//
// The check is diagnostic, not the security boundary: the TPM itself enforces
// the sealed object's policy at unseal time. A blob whose layout is not
// understood therefore disables the check with a debug warning instead of
// halting the boot — a false tamper alarm would lock the user out of a
// healthy system.
func verifyNVIndexIdentity(nvHandleBlob []byte, nvIndex uint32, livePublic []byte) error {
	if len(nvHandleBlob) == 0 {
		buildtags.Debug("tpm: WARNING: no NV handle blob in token, cannot verify NV index identity\n")
		return nil
	}

	blob, err := ParseESYSTrBlob(nvHandleBlob)
	if err != nil {
		buildtags.Debug("tpm: WARNING: cannot parse the token's NV handle blob: %v\n", err)
		return nil
	}
	if len(blob.NVPublic) == 0 {
		buildtags.Debug("tpm: WARNING: the token's NV handle blob carries no NV public area\n")
		return nil
	}
	if blob.Handle != nvIndex {
		// The blob describes another index than the one in use (the
		// token's index was invalid and a fallback index was selected).
		// Comparing names would produce a false alarm.
		buildtags.Debug("tpm: WARNING: the token's NV blob handle 0x%x differs from the NV index in use 0x%x — skipping the identity check\n", blob.Handle, nvIndex)
		return nil
	}

	expectedName, err := ComputeNVNameFromPublic(blob.NVPublic)
	if err != nil {
		buildtags.Debug("tpm: WARNING: failed to compute the expected NV name from the token: %v\n", err)
		return nil
	}
	liveName, err := ComputeNVNameFromPublic(livePublic)
	if err != nil {
		buildtags.Debug("tpm: WARNING: failed to compute the NV name of the live index: %v\n", err)
		return nil
	}

	if !bytes.Equal(expectedName, liveName) {
		buildtags.Debug("tpm: NV name mismatch!\n  expected: %x\n  actual:   %x\n", expectedName, liveName)
		return fmt.Errorf("NV index name mismatch — possible tampering detected (NV index may have been redefined)")
	}

	buildtags.Debug("tpm: NV index name verified against token\n")
	return nil
}
