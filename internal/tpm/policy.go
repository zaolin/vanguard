package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/zaolin/vanguard/init/buildtags"
)

// PCRLockPolicy represents a parsed pcrlock.json file with all the data
// needed to build a super-PCR policy session.
type PCRLockPolicy struct {
	NVIndex        uint32
	Bank           HashAlgorithm
	PCRPredictions []PCRPrediction
}

// computePolicyPCRHash computes the policy digest for a PolicyPCR command
// starting from currentDigest as the initial hash state.
// This is: H(current_digest || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || PCR_digest)
//
// If currentDigest is nil or empty, starts from all-zeros (fresh session).
// The marshalling follows TPM 2.0 Spec Part 2 format, verified against go-tpm's
// PolicyCalculator output.
//
// Currently only SHA256 is supported. If a different algorithm is passed, an
// error is returned rather than silently producing a wrong digest.
func computePolicyPCRHash(alg HashAlgorithm, currentDigest []byte, pcrDigest []byte, pcrSelection tpm2.TPMLPCRSelection) ([]byte, error) {
	if alg != AlgSHA256 {
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%x (only SHA256 supported)", alg)
	}

	state := currentDigest
	if len(state) == 0 {
		state = make([]byte, sha256.Size)
	}

	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(tpm2.TPMCCPolicyPCR))
	buf = append(buf, marshalPCRLSelection(pcrSelection)...)
	buf = append(buf, pcrDigest...)

	h := sha256.New()
	h.Write(state)
	h.Write(buf)
	return h.Sum(nil), nil
}

// computePolicyORHash computes the policy digest for a PolicyOR command.
// PolicyOR resets the state to zeros and extends:
// H(0x00...0 || TPM_CC_PolicyOR || branch1 || branch2 || ... || branchN)
//
// Currently only SHA256 is supported. If a different algorithm is passed, an
// error is returned rather than silently producing a wrong digest.
func computePolicyORHash(alg HashAlgorithm, branchDigests [][]byte) ([]byte, error) {
	if alg != AlgSHA256 {
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%x (only SHA256 supported)", alg)
	}

	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(tpm2.TPMCCPolicyOR))
	for _, d := range branchDigests {
		buf = append(buf, d...)
	}

	h := sha256.New()
	h.Write(make([]byte, sha256.Size))
	h.Write(buf)
	return h.Sum(nil), nil
}

// marshalPCRLSelection marshals a TPML_PCR_SELECTION per TPM 2.0 Spec Part 2:
// uint32 count, then per selection: uint16 hashAlg + uint8 sizeofSelect + []byte bitmap
func marshalPCRLSelection(sel tpm2.TPMLPCRSelection) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(sel.PCRSelections)))
	for _, s := range sel.PCRSelections {
		buf = binary.BigEndian.AppendUint16(buf, uint16(s.Hash))
		buf = append(buf, byte(len(s.PCRSelect)))
		buf = append(buf, s.PCRSelect...)
	}
	return buf
}

// computePCRDigest computes the aggregate PCR digest for a set of PCR values.
// The digest is SHA256(PCR0_value || PCR1_value || ... || PCRn_value) for SHA256 bank.
func computePCRDigest(alg HashAlgorithm, pcrValues map[int][]byte, pcrs []int) ([]byte, error) {
	switch alg {
	case AlgSHA256:
		h := sha256.New()
		for _, pcr := range pcrs {
			val, ok := pcrValues[pcr]
			if !ok {
				return nil, fmt.Errorf("missing PCR %d value", pcr)
			}
			h.Write(val)
		}
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%x", alg)
	}
}

// buildPCRLSelection creates a TPMLPCRSelection for the given PCR indices.
func buildPCRLSelection(alg HashAlgorithm, pcrs []int) tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr >= 0 && pcr < 24 {
			bitmap[pcr/8] |= 1 << (pcr % 8)
		}
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      alg,
			PCRSelect: bitmap,
		}},
	}
}

// buildSuperPCRPolicySession builds the super-PCR policy on the TPM by executing
// PolicyPCR and PolicyOR commands on a real policy session. This matches systemd's
// tpm2_policy_super_pcr:
//
//	Phase 1: Combined PolicyPCR for all single-value PCRs
//	Phase 2: For each multi-value PCR: compute all branches offline, then PolicyOR
//
// After this, the session digest should match the value stored in the NV index,
// so that PolicyAuthorizeNV will succeed.
func buildSuperPCRPolicySession(tpm transport.TPM, alg HashAlgorithm, predictions []PCRPrediction, sess tpm2.Session) error {
	var singleValuePCRs []int
	var multiValuePCRs []PCRPrediction

	for _, pred := range predictions {
		if len(pred.Values) == 1 {
			singleValuePCRs = append(singleValuePCRs, pred.PCR)
		} else if len(pred.Values) > 1 {
			multiValuePCRs = append(multiValuePCRs, pred)
		}
	}

	if len(singleValuePCRs) > 0 {
		pcrSelection := buildPCRLSelection(alg, singleValuePCRs)

		buildtags.Debug("tpm: PolicyPCR (single-value) for PCRs %v\n", singleValuePCRs)

		_, err := tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			PcrDigest:     tpm2.TPM2BDigest{},
			Pcrs:          pcrSelection,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("PolicyPCR (single-value) failed: %w", err)
		}
	}

	for _, pred := range multiValuePCRs {
		if len(pred.Values) == 0 {
			continue
		}

		pcrSel := buildPCRLSelection(alg, []int{pred.PCR})

		digestRsp, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("PolicyGetDigest before PCR %d: %w", pred.PCR, err)
		}
		previousDigest := digestRsp.PolicyDigest.Buffer
		buildtags.Debug("tpm: previous session digest before PCR %d: %x\n", pred.PCR, previousDigest)

		buildtags.Debug("tpm: PolicyPCR on session for PCR %d (empty PcrDigest, TPM uses current values)\n", pred.PCR)
		_, err = tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			PcrDigest:     tpm2.TPM2BDigest{},
			Pcrs:          pcrSel,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("PolicyPCR for PCR %d failed: %w", pred.PCR, err)
		}

		var branchDigests [][]byte
		for i, val := range pred.Values {
			pcrVals := map[int][]byte{pred.PCR: val}
			pcrDigest, err := computePCRDigest(alg, pcrVals, []int{pred.PCR})
			if err != nil {
				return fmt.Errorf("compute PCR digest for PCR %d variant %d: %w", pred.PCR, i, err)
			}

			branchDigest, err := computePolicyPCRHash(alg, previousDigest, pcrDigest, pcrSel)
			if err != nil {
				return fmt.Errorf("offline branch for PCR %d variant %d: %w", pred.PCR, i, err)
			}
			buildtags.Debug("tpm: PCR %d branch %d digest: %x\n", pred.PCR, i, branchDigest)
			branchDigests = append(branchDigests, branchDigest)
		}

		tpm2Digests := make([]tpm2.TPM2BDigest, len(branchDigests))
		for i, d := range branchDigests {
			tpm2Digests[i] = tpm2.TPM2BDigest{Buffer: d}
		}

		buildtags.Debug("tpm: PolicyOR for PCR %d with %d branches\n", pred.PCR, len(branchDigests))
		_, err = tpm2.PolicyOr{
			PolicySession: sess.Handle(),
			PHashList:     tpm2.TPMLDigest{Digests: tpm2Digests},
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("PolicyOR for PCR %d failed: %w", pred.PCR, err)
		}
	}

	return nil
}

// buildSuperPCRPolicyOffline computes the super-PCR policy digest entirely in software.
// This matches systemd's tpm2_policy_super_pcr logic:
//
//	Phase 1: Combined PolicyPCR for all single-value PCRs
//	Phase 2: For each multi-value PCR: compute all branches offline, then PolicyOR
//
// The result is the session digest that should match the NV index contents.
func buildSuperPCRPolicyOffline(alg HashAlgorithm, predictions []PCRPrediction) ([]byte, error) {
	var singleValuePCRs []int
	singleValues := make(map[int][]byte)
	var multiValuePCRs []PCRPrediction

	for _, pred := range predictions {
		if len(pred.Values) == 1 {
			singleValuePCRs = append(singleValuePCRs, pred.PCR)
			singleValues[pred.PCR] = pred.Values[0]
		} else if len(pred.Values) > 1 {
			multiValuePCRs = append(multiValuePCRs, pred)
		}
	}

	var currentDigest []byte

	if len(singleValuePCRs) > 0 {
		pcrDigest, err := computePCRDigest(alg, singleValues, singleValuePCRs)
		if err != nil {
			return nil, fmt.Errorf("compute single-value PCR digest: %w", err)
		}
		pcrSelection := buildPCRLSelection(alg, singleValuePCRs)

		currentDigest, err = computePolicyPCRHash(alg, nil, pcrDigest, pcrSelection)
		if err != nil {
			return nil, fmt.Errorf("compute PolicyPCR hash: %w", err)
		}
	}

	for _, pred := range multiValuePCRs {
		if len(pred.Values) == 0 {
			continue
		}

		pcrSel := buildPCRLSelection(alg, []int{pred.PCR})

		var branchDigests [][]byte
		for i, val := range pred.Values {
			pcrVals := map[int][]byte{pred.PCR: val}
			pcrDigest, err := computePCRDigest(alg, pcrVals, []int{pred.PCR})
			if err != nil {
				return nil, fmt.Errorf("compute PCR digest for PCR %d variant %d: %w", pred.PCR, i, err)
			}

			branchDigest, err := computePolicyPCRHash(alg, currentDigest, pcrDigest, pcrSel)
			if err != nil {
				return nil, fmt.Errorf("compute PolicyPCR branch for PCR %d variant %d: %w", pred.PCR, i, err)
			}
			branchDigests = append(branchDigests, branchDigest)
		}

		orDigest, err := computePolicyORHash(alg, branchDigests)
		if err != nil {
			return nil, fmt.Errorf("compute PolicyOR for PCR %d: %w", pred.PCR, err)
		}
		currentDigest = orDigest
	}

	if len(currentDigest) == 0 {
		currentDigest = make([]byte, sha256.Size)
	}

	return currentDigest, nil
}

// computePolicyAuthorizeNVHash computes the policy digest for PolicyAuthorizeNV.
// Per TPM 2.0 Spec Part 3, Section 23.22:
//
//	new_digest = H(0x00...0 || TPM_CC_PolicyAuthorizeNV || nvIndexName)
//
// This RESETS the session state to all-zeros before extending, matching the TPM behavior
// where PolicyAuthorizeNV replaces the entire session digest.
func computePolicyAuthorizeNVHash(nvName []byte) ([]byte, error) {
	state := make([]byte, sha256.Size)

	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(tpm2.TPMCCPolicyAuthorizeNV))
	buf = append(buf, nvName...)

	h := sha256.New()
	h.Write(state)
	h.Write(buf)
	return h.Sum(nil), nil
}

// computeNVName computes the TPM NV index name from a raw TPM2B_NV_PUBLIC blob.
// The name is: nameAlg (2 bytes) || H(TPMS_NV_PUBLIC), where the hash is SHA256
// for SHA256-nameAlg indexes (the only case vanguard supports).
//
// The TPM2B_NV_PUBLIC layout is:
//
//	[0:2]   TPM2B size (uint16)
//	[2:6]   NVIndex (uint32)
//	[6:8]   nameAlg (uint16)
//	[8:12]  attributes (uint32)
//	[12:14] authPolicy size (uint16)
//	[14:14+aps] authPolicy data
//	[14+aps:14+aps+2] dataSize (uint16)
//
// The name covers the TPMS_NV_PUBLIC (starting at offset 2, after the TPM2B size).
// If the blob doesn't start with a TPM2B size, we treat the entire blob as the
// TPMS_NV_PUBLIC (offset 0).
//
// Volatile attribute bits (Written, ReadLocked, WriteLocked) are masked out
// before hashing. These bits change at runtime (e.g. Written is set when
// make-policy writes the digest) and are not part of the NV index identity.
// Without masking, the name from the token's TPM2B_NV_PUBLIC (captured at
// enrollment, before writing) would never match the TPM's current name (which
// has Written=1 after make-policy runs).
//
// Returns the name (nameAlg || hash) or an error if the blob is too short.
func computeNVName(nvPublicBlob []byte) ([]byte, error) {
	if len(nvPublicBlob) < 8 {
		return nil, fmt.Errorf("NV public blob too short: %d bytes", len(nvPublicBlob))
	}

	// Determine where TPMS_NV_PUBLIC starts. If the first 2 bytes look like a
	// TPM2B size that roughly matches the remaining data, skip it.
	TPMSStart := 0
	declaredSize := int(binary.BigEndian.Uint16(nvPublicBlob[0:2]))
	if declaredSize > 0 && declaredSize <= len(nvPublicBlob)-2 && declaredSize >= 10 {
		TPMSStart = 2
	}

	tpmsData := nvPublicBlob[TPMSStart:]
	if len(tpmsData) < 12 {
		return nil, fmt.Errorf("TPMS_NV_PUBLIC too short: %d bytes", len(tpmsData))
	}

	nameAlg := int(binary.BigEndian.Uint16(tpmsData[4:6]))
	if nameAlg != int(tpm2.TPMAlgSHA256) {
		return nil, fmt.Errorf("unsupported NV name algorithm: 0x%x (only SHA256 supported)", nameAlg)
	}

	// Mask volatile attribute bits before hashing. The attributes field is a
	// 4-byte big-endian uint32 at offset 6 within TPMS_NV_PUBLIC (after
	// NVIndex[4] + nameAlg[2] = 6 bytes).
	// Volatile bits: WriteLocked (bit 11), ReadLocked (bit 28), Written (bit 29).
	const volatileMask = uint32(1<<11 | 1<<28 | 1<<29) // 0x30000800

	// Copy tpmsData so we don't modify the caller's slice
	hashData := make([]byte, len(tpmsData))
	copy(hashData, tpmsData)

	// Mask volatile bits in the attributes field (bytes 6-9 within TPMS_NV_PUBLIC)
	if len(hashData) >= 10 {
		attrs := binary.BigEndian.Uint32(hashData[6:10])
		attrs &^= volatileMask // clear volatile bits
		binary.BigEndian.PutUint32(hashData[6:10], attrs)
	}

	hash := sha256.Sum256(hashData)

	name := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(name[0:2], uint16(nameAlg))
	copy(name[2:], hash[:])

	return name, nil
}

// computePolicyAuthValueHash computes the policy digest for PolicyAuthValue.
// Per TPM 2.0 Spec Part 3, Section 23.17:
//
//	new_digest = H(current_digest || TPM_CC_PolicyAuthValue)
func computePolicyAuthValueHash(currentDigest []byte) ([]byte, error) {
	if len(currentDigest) == 0 {
		currentDigest = make([]byte, sha256.Size)
	}

	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(tpm2.TPMCCPolicyAuthValue))

	h := sha256.New()
	h.Write(currentDigest)
	h.Write(buf)
	return h.Sum(nil), nil
}

// ParsePCRLockJSON parses a pcrlock.json file and returns a PCRLockPolicy.
// The pcrlock.json format (from systemd-pcrlock make-policy) is:
//
//	{
//	  "pcrBank": "sha256",
//	  "pcrValues": [
//	    {"pcr": 0, "values": ["a1b2c3d4...hex"]},
//	    {"pcr": 7, "values": ["abc123...hex", "def456...hex"]}
//	  ],
//	  "nvIndex": 25165824,
//	  ...
//	}
func ParsePCRLockJSON(data []byte) (*PCRLockPolicy, error) {
	var raw struct {
		PCRBank   string `json:"pcrBank"`
		NVIndex   uint32 `json:"nvIndex"`
		PCRValues []struct {
			PCR    int      `json:"pcr"`
			Values []string `json:"values"`
		} `json:"pcrValues"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse pcrlock.json: %w", err)
	}

	policy := &PCRLockPolicy{
		NVIndex: raw.NVIndex,
		Bank:    ParsePCRBank(raw.PCRBank),
	}

	for _, pv := range raw.PCRValues {
		pred := PCRPrediction{
			PCR:    pv.PCR,
			Values: make([][]byte, len(pv.Values)),
		}
		for i, hexVal := range pv.Values {
			val, err := hex.DecodeString(hexVal)
			if err != nil {
				return nil, fmt.Errorf("decode PCR %d value %d: %w", pv.PCR, i, err)
			}
			pred.Values[i] = val
		}
		policy.PCRPredictions = append(policy.PCRPredictions, pred)
	}

	return policy, nil
}

// --- TOTP Recovery Seed Policy ---

// SeedReadPolicyPCRs defines the PCR sets for each branch of the PolicyOR
// that protects the TOTP recovery seed. All branches require PCR 7 (Secure
// Boot state) — without Secure Boot, the initrd cannot be trusted and the
// seed is never released.
//
// Single branch: PCR 7 only — the seed is released when Secure Boot is
// active and matches the enrollment-time state. When Secure Boot keys
// change (e.g., firmware update resets PK/KEK/db), the seed becomes
// inaccessible and must be re-provisioned via 'vanguard recovery --auto-reseed'
// or 'vanguard recovery --clean --enable'.
//
// Previous versions used 3 branches ({4,7}, {7}, {0,7}) but analysis showed
// that branch {7} alone covers all valid cases (kernel updates, firmware
// updates) while rejecting all invalid cases (Secure Boot disabled, live USB
// boot). The extra branches provided no additional coverage since PolicyOR
// is satisfied by the weakest branch.
var SeedReadPolicyPCRs = [][]int{
	{7}, // Single branch: Secure Boot state
}

// computeSeedReadPolicy computes the authPolicy for the TOTP recovery seed
// NV index. With the single-branch policy (PCR 7 only), the authPolicy is
// just the PolicyPCR digest — no PolicyOR is needed (the TPM requires at
// least 2 branches for PolicyOR).
//
// Parameters:
//   - alg: hash algorithm (must be AlgSHA256)
//   - pcrValues: map of PCR number → current PCR value (at enrollment time)
//
// Returns the 32-byte PolicyPCR digest.
func computeSeedReadPolicy(alg HashAlgorithm, pcrValues map[int][]byte) ([]byte, error) {
	if alg != AlgSHA256 {
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%x (only SHA256)", alg)
	}

	// Single branch: compute PolicyPCR digest directly
	pcrSet := SeedReadPolicyPCRs[0]
	pcrDigest, err := computePCRDigest(alg, pcrValues, pcrSet)
	if err != nil {
		return nil, fmt.Errorf("compute PCR digest for %v: %w", pcrSet, err)
	}

	sel := buildPCRLSelection(alg, pcrSet)
	branchDigest, err := computePolicyPCRHash(alg, nil, pcrDigest, sel)
	if err != nil {
		return nil, fmt.Errorf("compute PolicyPCR for %v: %w", pcrSet, err)
	}

	return branchDigest, nil
}
