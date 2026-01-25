package pcrlock

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Policy represents the structure of the pcrlock.json policy file
type Policy struct {
	NVIndex   int        `json:"nvIndex"`
	NVPublic  string     `json:"nvPublic"`
	NVHandle  string     `json:"nvHandle"`
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

// VerifyNVIndex checks if the TPM NV Index matches the policy expectation
func VerifyNVIndex(policy *Policy) (*NVIndexDetails, bool, error) {
	details, err := ReadNVIndexDetails(policy.NVIndex)
	if err != nil {
		return nil, false, err
	}

	_, expectedAuthPolicy, expectedSize, err := extractNVPublicDetails(policy.NVPublic)
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

// ReadNVIndexDetails reads NV Index details using tpm2_nvreadpublic
func ReadNVIndexDetails(index int) (*NVIndexDetails, error) {
	cmd := exec.Command("tpm2_nvreadpublic", fmt.Sprintf("0x%x", index))
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%v: %s", err, string(exitErr.Stderr))
		}
		return nil, err // likely index not found or TPM error
	}

	details := &NVIndexDetails{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				details.Name = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "authorization policy:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				details.AuthPolicy = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "size:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &details.Size)
			}
		} else if strings.HasPrefix(line, "friendly:") && details.Attributes == "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				details.Attributes = strings.TrimSpace(parts[1])
			}
		}
	}

	return details, nil
}

// extractNVPublicDetails extracts name, authPolicy and dataSize from base64-encoded TPM2B_NV_PUBLIC
func extractNVPublicDetails(nvPublicB64 string) (name, authPolicy string, dataSize int, err error) {
	data, err := base64.StdEncoding.DecodeString(nvPublicB64)
	if err != nil {
		return "", "", 0, fmt.Errorf("base64 decode failed: %w", err)
	}

	if len(data) < 14 {
		return "", "", 0, fmt.Errorf("nvPublic too short: %d bytes", len(data))
	}

	nameAlg := int(data[6])<<8 | int(data[7])
	offset := 12

	authPolicySize := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+authPolicySize > len(data) {
		return "", "", 0, fmt.Errorf("authPolicy truncated")
	}
	authPolicy = fmt.Sprintf("%X", data[offset:offset+authPolicySize])
	offset += authPolicySize

	if offset+2 > len(data) {
		return "", "", 0, fmt.Errorf("dataSize truncated")
	}
	dataSize = int(data[offset])<<8 | int(data[offset+1])

	nvPublicContent := data[2:]
	hash := sha256.Sum256(nvPublicContent)
	name = fmt.Sprintf("%04X%X", nameAlg, hash[:])

	return name, authPolicy, dataSize, nil
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

	pcrList := make([]string, len(pcrsToRead))
	for i, pcr := range pcrsToRead {
		pcrList[i] = fmt.Sprintf("%d", pcr)
	}
	pcrArg := "sha256:" + strings.Join(pcrList, ",")

	cmd := exec.Command("tpm2_pcrread", pcrArg)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tpm2_pcrread failed: %w", err)
	}

	pcrs := make(map[int]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		var pcr int
		if _, err := fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &pcr); err != nil {
			continue
		}

		value := strings.TrimSpace(parts[1])
		value = strings.TrimPrefix(value, "0x")
		value = strings.TrimPrefix(value, "0X")
		pcrs[pcr] = strings.ToLower(value)
	}

	return pcrs, nil
}
