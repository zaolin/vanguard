package pcrlock

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm"
)

// Policy represents the structure of the pcrlock.json policy file
type Policy struct {
	NVIndex   int        `json:"nvIndex"`
	NVPublic  string     `json:"nvPublic"`
	PCRValues []PCRValue `json:"pcrValues"`
}

// PCRValue represents expected PCR values in the policy
type PCRValue struct {
	PCR    int      `json:"pcr"`
	Values []string `json:"values"`
}

// NVIndexDetails holds parsed info from tpm2_nvreadpublic
type NVIndexDetails struct {
	Name       string
	AuthPolicy string
	Size       int
	Attributes string
}

// ParsePolicy reads and parses a pcrlock policy file
func ParsePolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}
	return &policy, nil
}

// VerifyNVIndex checks if the TPM NV Index matches the policy expectation.
// It compares the auth policy and data size against the values derived from
// the policy's base64-encoded nvPublic field.
//
// The NV index name is NOT compared here because it includes volatile
// attribute bits (Written, ReadLocked, WriteLocked) that change at runtime
// when make-policy writes the digest. The TPM computes the name in hardware
// with the current attribute state (Written=1), while the policy's nvPublic
// was captured before the write (Written=0) — so the names will always differ
// by those volatile bits. The full NV name verification with volatile bit
// masking happens only in the boot-time unseal path (internal/tpm/tpm.go:
// unsealWithPCRLock), where both sides are in software and volatile bits can
// be masked on both.
func VerifyNVIndex(policy *Policy) (*NVIndexDetails, bool, error) {
	details, err := ReadNVIndexDetails(policy.NVIndex)
	if err != nil {
		return nil, false, err
	}

	expectedAuthPolicy, expectedSize, err := extractNVPublicDetails(policy.NVPublic)
	if err != nil {
		return details, false, fmt.Errorf("failed to decode nvPublic from policy: %w", err)
	}

	matches := true
	if !strings.EqualFold(details.AuthPolicy, expectedAuthPolicy) {
		matches = false
	}
	if details.Size != expectedSize {
		matches = false
	}

	return details, matches, nil
}

// ReadNVIndexDetails reads NV Index details using native go-tpm2.
func ReadNVIndexDetails(index int) (*NVIndexDetails, error) {
	tpmClient := tpm.New()

	detailed, err := tpmClient.ListNVIndexesDetailed()
	if err != nil {
		return nil, fmt.Errorf("failed to list NV indexes: %w", err)
	}

	for _, info := range detailed {
		if int(info.Index) != index {
			continue
		}
		details := &NVIndexDetails{
			Name:       hex.EncodeToString(info.Name),
			AuthPolicy: hex.EncodeToString(info.AuthPolicy),
			Size:       int(info.DataSize),
			Attributes: nvAttributesToString(info.Attributes),
		}
		return details, nil
	}

	return nil, fmt.Errorf("NV index 0x%x not found", index)
}

// nvAttributesToString converts TPMA_NV attributes to a human-readable string.
func nvAttributesToString(attrs tpm2.TPMANV) string {
	var parts []string
	if attrs.PPWrite {
		parts = append(parts, "ppwrite")
	}
	if attrs.OwnerWrite {
		parts = append(parts, "ownerwrite")
	}
	if attrs.AuthWrite {
		parts = append(parts, "authwrite")
	}
	if attrs.PolicyWrite {
		parts = append(parts, "policywrite")
	}
	if attrs.OwnerRead {
		parts = append(parts, "ownerread")
	}
	if attrs.AuthRead {
		parts = append(parts, "authread")
	}
	if attrs.PolicyRead {
		parts = append(parts, "policyread")
	}
	if attrs.PlatformCreate {
		parts = append(parts, "platformcreate")
	}
	if attrs.OwnerRead {
		parts = append(parts, "ownerread")
	}
	return strings.Join(parts, ",")
}

// extractNVPublicDetails extracts authPolicy and dataSize from base64-encoded
// TPM2B_NV_PUBLIC. The name is no longer computed here — NV name verification
// with volatile bit masking is handled in the boot-time unseal path
// (internal/tpm/tpm.go: unsealWithPCRLock) where both the token blob and the
// TPM response are in software and volatile bits can be masked on both sides.
func extractNVPublicDetails(nvPublicB64 string) (authPolicy string, dataSize int, err error) {
	data, err := base64.StdEncoding.DecodeString(nvPublicB64)
	if err != nil {
		return "", 0, fmt.Errorf("base64 decode failed: %w", err)
	}

	if len(data) < 14 {
		return "", 0, fmt.Errorf("nvPublic too short: %d bytes", len(data))
	}

	// nameAlg is at data[6:8] (after TPM2B size[2] + NVIndex[4])
	// authPolicySize is at data[12:14] (after TPM2B size[2] + NVIndex[4] + nameAlg[2] + attributes[4])
	offset := 12

	authPolicySize := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+authPolicySize > len(data) {
		return "", 0, fmt.Errorf("authPolicy truncated")
	}
	authPolicy = fmt.Sprintf("%X", data[offset:offset+authPolicySize])
	offset += authPolicySize

	if offset+2 > len(data) {
		return "", 0, fmt.Errorf("dataSize truncated")
	}
	dataSize = int(data[offset])<<8 | int(data[offset+1])

	return authPolicy, dataSize, nil
}

// PCRNames maps PCR numbers to human-readable names
// Exported so we don't have to redefine it
var PCRNames = map[int]string{
	0:  "platform-code",
	1:  "platform-config",
	2:  "external-code",
	3:  "external-config",
	4:  "boot-loader-code",
	5:  "boot-loader-config",
	7:  "secure-boot-policy",
	9:  "kernel-cmdline",
	11: "kernel-boot",
	12: "kernel-config",
	13: "sysexts",
	14: "shim-policy",
	15: "system-identity",
}

// VerifyPCRs checks if current PCR values match one of the allowed values in the policy
// Returns a map of matches (true/false) and the current value for each checked PCR
func VerifyPCRs(policy *Policy) (map[int]bool, map[int]string, error) {
	var requiredPCRs []int
	for _, pv := range policy.PCRValues {
		requiredPCRs = append(requiredPCRs, pv.PCR)
	}

	currentPCRs, err := readCurrentPCRs(requiredPCRs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	matches := make(map[int]bool)
	currentValues := make(map[int]string)

	for _, pv := range policy.PCRValues {
		pcr := pv.PCR
		current := strings.ToLower(currentPCRs[pcr])
		currentValues[pcr] = current

		matched := false
		for _, v := range pv.Values {
			if strings.ToLower(v) == current {
				matched = true
				break
			}
		}
		matches[pcr] = matched
	}

	return matches, currentValues, nil
}

func readCurrentPCRs(pcrsToRead []int) (map[int]string, error) {
	if len(pcrsToRead) == 0 {
		return make(map[int]string), nil
	}

	tpmClient := tpm.New()
	pcrValues, err := tpmClient.ReadPCRs(tpm.AlgSHA256, pcrsToRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	pcrs := make(map[int]string)
	for pcr, value := range pcrValues {
		pcrs[pcr] = hex.EncodeToString(value)
	}

	return pcrs, nil
}
