package pcrlock

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"

	"github.com/zaolin/vanguard/internal/tpm"
)

// LUKSTPMToken represents the systemd-tpm2 token data from a LUKS device
type LUKSTPMToken struct {
	Type     string `json:"type"`
	NVIndex  int    // NV index the token is bound to (from the ESYS_TR blob)
	NVHandle string // base64 serialized ESYS_TR of the NV index (token field tpm2_pcrlock_nv)
	PCRs     []int  `json:"tpm2-pcrs,omitempty"`
	HasPIN   bool   `json:"tpm2-pin,omitempty"`
	// HasPCRLock reports whether the token is bound to a pcrlock NV
	// index at all. A classic PCR-bound token has no NV binding, so the
	// pcrlock policy does not apply to it.
	HasPCRLock bool `json:"tpm2_pcrlock,omitempty"`
}

// minNVIndex/maxNVIndex bound the pcrlock owner-hierarchy NV index range
// (0x01800000–0x01BFFFFF), plus the legacy default 0x01C20000.
const (
	minPcrlockNVIndex = 0x01800000
	maxPcrlockNVIndex = 0x01BFFFFF
	legacyPcrlockNV   = 0x01C20000
)

// IsPcrlockNVIndex reports whether idx falls in the pcrlock owner NV index
// range (0x01800000–0x01BFFFFF) or the legacy default 0x01C20000. This is
// the single validator for all pcrlock NV index parsing; vanguard's own
// recovery indexes (0x01C3000x) are deliberately excluded.
func IsPcrlockNVIndex(idx uint32) bool {
	return (idx >= minPcrlockNVIndex && idx <= maxPcrlockNVIndex) || idx == legacyPcrlockNV
}

// ParseNVIndexFromBlob extracts the pcrlock NV index from a base64-encoded
// token blob (the tpm2_pcrlock_nv field, systemd v255+).
//
// systemd stores the serialized ESYS_TR of the NV index there, not a bare
// TPM2B_NV_PUBLIC. Its layout (tpm2-tss, src/tss2-esys/esys_types.h) is:
//
//	[0:4]   handle (TPM2_HANDLE) — the NV index itself
//	[4:6]   name size (uint16)
//	[6:..]  name (algorithm + digest)
//	[..:..] resource type (uint32)
//	[..:..] TPM2B_NV_PUBLIC
//
// Real-world systemd versions have also produced bare TPM2B_NV_PUBLIC
// blobs, so the spec-compliant layout (NVIndex at offset 2, after the TPM2B
// size prefix) is tried as a fallback.
//
// Returns 0 and an error when no in-range index can be found. Never returns
// an unvalidated value — callers rely on this for TPM NV cleanup decisions.
func ParseNVIndexFromBlob(b64 string) (uint32, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, fmt.Errorf("failed to decode base64: %w", err)
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("blob too short: %d bytes", len(data))
	}

	// Primary strategy: the serialized ESYS_TR of the NV index. The handle
	// at offset 0 is the NV index; requiring a well-formed name prevents a
	// bare TPM2B_NV_PUBLIC from being misread.
	if blob, err := tpm.ParseESYSTrBlob(data); err == nil {
		if IsPcrlockNVIndex(blob.Handle) {
			return blob.Handle, nil
		}
	}

	// Fallback: spec-compliant TPM2B_NV_PUBLIC — NVIndex at offset 2.
	if len(data) >= 6 {
		if idx := binary.BigEndian.Uint32(data[2:6]); IsPcrlockNVIndex(idx) {
			return idx, nil
		}
	}

	// Fallback: legacy unwrapped layout — NVIndex at offset 0.
	if idx := binary.BigEndian.Uint32(data[0:4]); IsPcrlockNVIndex(idx) {
		return idx, nil
	}

	return 0, fmt.Errorf("no valid pcrlock NV index found in blob (%d bytes)", len(data))
}

// ErrNoTPMToken reports that the device carries no systemd-tpm2 token at
// all. It is distinct from a failed lookup: callers deciding whether a fresh
// NV index may be allocated must not treat an unreadable device as "nothing
// enrolled".
var ErrNoTPMToken = errors.New("no systemd-tpm2 token found on device")

// luksDumpRunner reads the LUKS2 JSON metadata of a device. It is a package
// variable so the token lookup itself can be tested without a real device.
var luksDumpRunner = func(devicePath string) ([]byte, error) {
	return exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", devicePath).Output()
}

// GetLUKSTPMToken retrieves the TPM2 token information from a LUKS device
func GetLUKSTPMToken(devicePath string) (*LUKSTPMToken, error) {
	output, err := luksDumpRunner(devicePath)
	if err != nil {
		return nil, fmt.Errorf("luksDump failed: %w", err)
	}

	var dump struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(output, &dump); err != nil {
		return nil, fmt.Errorf("failed to parse LUKS dump: %w", err)
	}

	// Find systemd-tpm2 token. The tokens are decoded into a map, and Go
	// randomizes map iteration order — iterate the token IDs in sorted
	// order so the same token is always selected (status output and the
	// NV-index comparison in `vanguard update` must be stable).
	//
	// The IDs are the LUKS2 header token numbers as decimal strings, so they
	// must be ordered NUMERICALLY: a lexicographic sort would select token 10
	// before token 2 and could prefer a classic token over the pcrlock one.
	tokenIDs := make([]string, 0, len(dump.Tokens))
	for id := range dump.Tokens {
		tokenIDs = append(tokenIDs, id)
	}
	sort.Slice(tokenIDs, func(i, j int) bool {
		a, errA := strconv.Atoi(tokenIDs[i])
		b, errB := strconv.Atoi(tokenIDs[j])
		if errA == nil && errB == nil && a != b {
			return a < b
		}
		return tokenIDs[i] < tokenIDs[j] // non-numeric IDs: stable fallback
	})

	var (
		decodeErr error
		found     *LUKSTPMToken
	)
	for _, id := range tokenIDs {
		tokenData := dump.Tokens[id]

		// Determine the token type first: only systemd-tpm2 tokens matter,
		// and a decode failure of an unrelated token type (fido2, pkcs11)
		// must not fail the lookup.
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(tokenData, &header); err != nil {
			decodeErr = fmt.Errorf("token %s cannot be decoded: %w", id, err)
			continue
		}
		if header.Type != "systemd-tpm2" {
			continue
		}

		var token struct {
			PCRs   []int `json:"tpm2-pcrs,omitempty"`
			HasPIN bool  `json:"tpm2-pin,omitempty"`
			// systemd uses both hyphen and underscore spellings across
			// versions — accept both (matches init/luks/token.go).
			HasPCRLock    bool   `json:"tpm2-pcrlock,omitempty"`
			HasPCRLockAlt bool   `json:"tpm2_pcrlock,omitempty"`
			PCRLockNV     string `json:"tpm2_pcrlock_nv,omitempty"`
		}
		if err := json.Unmarshal(tokenData, &token); err != nil {
			// A systemd-tpm2 token that cannot be decoded is neither "no
			// token" nor a classic token: the device's pcrlock state stays
			// unknown, and reporting a different, well-formed token would
			// hide that.
			decodeErr = fmt.Errorf("systemd-tpm2 token %s cannot be decoded: %w", id, err)
			continue
		}

		if found != nil {
			continue // keep the first usable token (sorted token IDs)
		}

		tpmToken := &LUKSTPMToken{
			Type:       header.Type,
			PCRs:       token.PCRs,
			HasPIN:     token.HasPIN,
			HasPCRLock: token.HasPCRLock || token.HasPCRLockAlt,
		}

		// Extract the NV index binding from the tpm2_pcrlock_nv blob. The
		// blob is the serialized ESYS_TR of the NV index; keep it verbatim:
		// it is the same artifact the policy file carries in its nvHandle
		// field, which is what makes a staleness check possible at all.
		if token.PCRLockNV != "" {
			nvIndex, err := extractNVIndexFromBlob(token.PCRLockNV)
			if err == nil {
				tpmToken.NVIndex = nvIndex
			}
			tpmToken.NVHandle = token.PCRLockNV
		}

		found = tpmToken
	}

	if decodeErr != nil {
		return nil, decodeErr
	}
	if found != nil {
		return found, nil
	}
	return nil, ErrNoTPMToken
}

// extractNVIndexFromBlob extracts the NV index from the token's base64-encoded
// NV binding blob using the shared validated parser.
func extractNVIndexFromBlob(b64 string) (int, error) {
	idx, err := ParseNVIndexFromBlob(b64)
	if err != nil {
		return 0, err
	}
	return int(idx), nil
}

// TokenMatchesPolicy reports whether the LUKS token can still unseal under
// the given policy, i.e. whether the token is stale and needs re-sealing.
//
// systemd stores, in the token field "tpm2_pcrlock_nv", the serialized
// ESYS_TR of the pcrlock NV index. The policy file carries the very same
// artifact in its "nvHandle" field. systemd itself matches the two byte by
// byte to find the policy that belongs to a token (see
// tpm2_pcrlock_policy_from_credentials in systemd's tpm2-util.c).
//
// Comparing the two therefore answers exactly the question the repair needs:
// does the token still point at the NV index that the current policy
// describes? A policy regeneration undefines and redefines the index, which
// can give it a new public area and therefore a new NV name. The sealed blob
// is bound to that name (PolicyAuthorizeNV folds the NV name into the session
// digest), so the old token can no longer unseal although the index number is
// unchanged. An identical redefinition keeps the token valid, and the blob
// comparison reports that correctly.
//
// A token that carries no "tpm2_pcrlock_nv" blob is a classic PCR-bound
// token: the pcrlock NV index does not apply to it, so it is never stale.
//
// The check cannot detect a policy whose PCR values changed while the NV
// index kept its identity: the token does not carry the policy digest, only
// the index handle.
func TokenMatchesPolicy(token *LUKSTPMToken, policy *Policy) (bool, error) {
	if token == nil || policy == nil {
		return false, fmt.Errorf("token and policy are required")
	}

	if token.HasPCRLock && token.NVHandle == "" {
		// The token declares pcrlock but carries no NV blob: its binding
		// cannot be checked at all. That is undecidable, not fresh.
		return false, fmt.Errorf("the token declares pcrlock but carries no tpm2_pcrlock_nv blob — its NV binding cannot be verified")
	}

	if token.NVHandle == "" {
		// Classic PCR-bound token — the pcrlock NV index does not apply.
		return false, nil
	}

	if len(token.PCRs) > 0 {
		// Hybrid token: pcrlock AND direct PCR binding. systemd permits
		// that combination (only signed PCR policies are rejected with
		// pcrlock). The NV blob comparison says nothing about the direct
		// PCR part, which breaks on a PCR change even when the NV index
		// is untouched — so this token's usability is undecidable here.
		return false, fmt.Errorf("the token combines pcrlock with direct PCR binding (tpm2-pcrs=%v) — its usability cannot be decided from the NV binding alone", token.PCRs)
	}

	if policy.NVHandle == "" {
		// The policy does not describe an NV index the token could be
		// bound to. Reporting the token as fresh would be wrong, and so
		// would be reporting it as stale: the state is unknown.
		return false, fmt.Errorf("policy carries no nvHandle — the token's NV binding cannot be verified")
	}

	// Compare the decoded blobs, not their base64 spelling: systemd matches
	// the two byte by byte, and different encoders may pad differently.
	tokenBlob, err := base64.StdEncoding.DecodeString(token.NVHandle)
	if err != nil {
		return false, fmt.Errorf("token tpm2_pcrlock_nv is not valid base64: %w", err)
	}
	policyBlob, err := base64.StdEncoding.DecodeString(policy.NVHandle)
	if err != nil {
		return false, fmt.Errorf("policy nvHandle is not valid base64: %w", err)
	}

	return !bytes.Equal(tokenBlob, policyBlob), nil
}
