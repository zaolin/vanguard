package pcrlock

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os/exec"
)

// LUKSTPMToken represents the systemd-tpm2 token data from a LUKS device
type LUKSTPMToken struct {
	Type       string `json:"type"`
	NVIndex    int    // Extracted from tpm2_pcrlock_nv blob
	PCRs       []int  `json:"tpm2-pcrs,omitempty"`
	HasPIN     bool   `json:"tpm2-pin,omitempty"`
	HasPCRLock bool   `json:"tpm2_pcrlock,omitempty"`
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

// ParseNVIndexFromBlob extracts the NV index from a base64-encoded
// TPM2B_NV_PUBLIC blob (the tpm2_pcrlock_nv token field, systemd v255+).
//
// Layout (TPM 2.0 Spec Part 2, §13.6):
//
//	[0:2]   TPM2B size (uint16)
//	[2:6]   NVIndex (uint32)
//	[6:8]   nameAlg
//	[8:12]  attributes
//	[12:14] authPolicy size
//	...
//
// Real-world systemd versions have used different offsets, so two strategies
// are tried in order, each validated against the pcrlock NV index range:
//
//  1. Spec-compliant: NVIndex at offset 2 (after the TPM2B size prefix)
//  2. Legacy: NVIndex at offset 0 (older systemd omitted the TPM2B wrapper)
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

	// Strategy 1: spec-compliant TPM2B_NV_PUBLIC — NVIndex at offset 2.
	if len(data) >= 6 {
		if idx := binary.BigEndian.Uint32(data[2:6]); IsPcrlockNVIndex(idx) {
			return idx, nil
		}
	}

	// Strategy 2: legacy unwrapped layout — NVIndex at offset 0.
	if idx := binary.BigEndian.Uint32(data[0:4]); IsPcrlockNVIndex(idx) {
		return idx, nil
	}

	return 0, fmt.Errorf("no valid pcrlock NV index found in blob (%d bytes)", len(data))
}

// GetLUKSTPMToken retrieves the TPM2 token information from a LUKS device
func GetLUKSTPMToken(devicePath string) (*LUKSTPMToken, error) {
	cmd := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", devicePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("luksDump failed: %w", err)
	}

	var dump struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(output, &dump); err != nil {
		return nil, fmt.Errorf("failed to parse LUKS dump: %w", err)
	}

	// Find systemd-tpm2 token
	for _, tokenData := range dump.Tokens {
		var token struct {
			Type   string `json:"type"`
			PCRs   []int  `json:"tpm2-pcrs,omitempty"`
			HasPIN bool   `json:"tpm2-pin,omitempty"`
			// systemd uses both hyphen and underscore spellings across
			// versions — accept both (matches init/luks/token.go).
			HasPCRLock    bool   `json:"tpm2-pcrlock,omitempty"`
			HasPCRLockAlt bool   `json:"tpm2_pcrlock,omitempty"`
			PCRLockNV     string `json:"tpm2_pcrlock_nv,omitempty"`
		}
		if err := json.Unmarshal(tokenData, &token); err != nil {
			continue
		}
		if token.Type == "systemd-tpm2" {
			tpmToken := &LUKSTPMToken{
				Type:       token.Type,
				PCRs:       token.PCRs,
				HasPIN:     token.HasPIN,
				HasPCRLock: token.HasPCRLock || token.HasPCRLockAlt,
			}

			// Extract NV index from tpm2_pcrlock_nv blob if present
			if token.PCRLockNV != "" {
				nvIndex, err := extractNVIndexFromBlob(token.PCRLockNV)
				if err == nil {
					tpmToken.NVIndex = nvIndex
				}
			}

			return tpmToken, nil
		}
	}

	return nil, fmt.Errorf("no systemd-tpm2 token found on device")
}

// extractNVIndexFromBlob extracts the NV index from a base64-encoded
// TPM2B_NV_PUBLIC blob using the shared validated parser.
func extractNVIndexFromBlob(b64 string) (int, error) {
	idx, err := ParseNVIndexFromBlob(b64)
	if err != nil {
		return 0, err
	}
	return int(idx), nil
}
