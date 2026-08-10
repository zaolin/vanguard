package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

func (c *VerifyPCRLockCmd) Run() error {
	policy, err := pcrlock.ParsePolicy(c.PolicyPath)
	if err != nil {
		return err
	}

	if c.JSON {
		return c.runJSON(policy)
	}

	return c.runHuman(policy)
}

// verifyResult is the JSON output structure for `vanguard verify --json`.
type verifyResult struct {
	Policy   string       `json:"policy"`
	NVIndex  int          `json:"nvIndex"`
	NVMatch  bool         `json:"nvMatch"`
	NVError  string       `json:"nvError,omitempty"`
	PCRs     []verifyPCR  `json:"pcrs"`
	Token    *verifyToken `json:"token,omitempty"`
	AllMatch bool         `json:"allMatch"`
}

type verifyPCR struct {
	PCR      int    `json:"pcr"`
	Name     string `json:"name"`
	Match    bool   `json:"match"`
	Enforced bool   `json:"enforced"`
	Current  string `json:"current,omitempty"`
}

type verifyToken struct {
	NVIndex    int  `json:"nvIndex"`
	HasPCRLock bool `json:"hasPcrlock"`
	NVMatch    bool `json:"nvMatch"`
}

func (c *VerifyPCRLockCmd) runJSON(policy *pcrlock.Policy) error {
	result := verifyResult{
		Policy:  c.PolicyPath,
		NVIndex: policy.NVIndex,
	}

	nvDetails, nvMatch, nvErr := pcrlock.VerifyNVIndex(policy)
	if nvErr != nil {
		result.NVError = nvErr.Error()
	} else {
		result.NVMatch = nvMatch
		_ = nvDetails
	}

	pcrMatches, currentValues, pcrErr := pcrlock.VerifyPCRs(policy)
	if pcrErr != nil {
		return fmt.Errorf("failed to read PCRs: %w", pcrErr)
	}

	result.AllMatch = result.NVMatch

	for _, pv := range policy.PCRValues {
		name := pcrlock.PCRNames[pv.PCR]
		if name == "" {
			name = "unknown"
		}

		isEnforced := true
		for _, v := range pv.Values {
			if v != "0000000000000000000000000000000000000000000000000000000000000000" {
				isEnforced = false
				break
			}
		}
		isEnforced = !isEnforced

		matched := pcrMatches[pv.PCR]
		current := currentValues[pv.PCR]

		result.PCRs = append(result.PCRs, verifyPCR{
			PCR:      pv.PCR,
			Name:     name,
			Match:    matched,
			Enforced: isEnforced,
			Current:  current,
		})

		if !matched && isEnforced {
			result.AllMatch = false
		}
	}

	if c.LUKSDevice != "" {
		token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice)
		if err == nil && token != nil {
			result.Token = &verifyToken{
				NVIndex:    token.NVIndex,
				HasPCRLock: token.HasPCRLock,
				NVMatch:    token.NVIndex == policy.NVIndex,
			}
			if !result.Token.NVMatch {
				result.AllMatch = false
			}
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))

	if !result.AllMatch {
		return fmt.Errorf("verification failed")
	}
	return nil
}

func (c *VerifyPCRLockCmd) runHuman(policy *pcrlock.Policy) error {

	fmt.Println()
	fmt.Println("  " + headerSty.Render("VERIFYING PCRLOCK SETUP"))
	fmt.Println()

	allMatch := true

	// NV Index section
	var nvLines []string
	nvLines = append(nvLines, fmt.Sprintf("Policy: %s", c.PolicyPath))
	nvLines = append(nvLines, fmt.Sprintf("NV Index: 0x%x", policy.NVIndex))
	nvLines = append(nvLines, "")

	nvDetails, nvMatch, nvErr := pcrlock.VerifyNVIndex(policy)
	if nvErr != nil {
		nvLines = append(nvLines, errStyle.Render(fmt.Sprintf("✗ Failed to read NV: %v", nvErr)))
		allMatch = false
	} else if nvMatch {
		nvLines = append(nvLines, fmt.Sprintf("%s Auth policy matches", okStyle.Render("✓")))
		nvLines = append(nvLines, fmt.Sprintf("%s Size: %d bytes", okStyle.Render("✓"), nvDetails.Size))
	} else {
		nvLines = append(nvLines, errStyle.Render("✗ NV index mismatch"))
		if nvDetails != nil {
			nvLines = append(nvLines, fmt.Sprintf("  Auth policy: %s", truncateHash(nvDetails.AuthPolicy)))
			nvLines = append(nvLines, fmt.Sprintf("  Size: %d bytes", nvDetails.Size))
		}
		nvLines = append(nvLines, dimStyle.Render("  Run: vanguard update"))
		allMatch = false
	}
	fmt.Println(box("NV Index Synchronization", nvLines))

	// PCR Validation section
	pcrMatches, currentValues, pcrErr := pcrlock.VerifyPCRs(policy)
	if pcrErr != nil {
		return fmt.Errorf("failed to read PCRs: %w", pcrErr)
	}

	var requiredPCRs []int
	for _, pv := range policy.PCRValues {
		requiredPCRs = append(requiredPCRs, pv.PCR)
	}
	sort.Ints(requiredPCRs)

	var pcrLines []string
	pcrAllMatch := true
	for _, pcr := range requiredPCRs {
		name := pcrlock.PCRNames[pcr]
		if name == "" {
			name = "unknown"
		}

		isEnforced := true
		for _, pv := range policy.PCRValues {
			if pv.PCR == pcr {
				allZero := true
				for _, v := range pv.Values {
					if v != "0000000000000000000000000000000000000000000000000000000000000000" {
						allZero = false
						break
					}
				}
				isEnforced = !allZero
				break
			}
		}

		matched := pcrMatches[pcr]
		current := currentValues[pcr]

		if matched {
			pcrLines = append(pcrLines, fmt.Sprintf("%s PCR %-2d %s", okStyle.Render("✓"), pcr, name))
		} else {
			icon := errStyle.Render("✗")
			suffix := ""
			if isEnforced {
				suffix = errStyle.Render(" — MISMATCH")
				pcrAllMatch = false
			} else {
				icon = dimStyle.Render("—")
				suffix = dimStyle.Render(" (all-zeros)")
			}
			pcrLines = append(pcrLines, fmt.Sprintf("%s PCR %-2d %s%s", icon, pcr, name, suffix))
			if current != "" {
				pcrLines = append(pcrLines, dimStyle.Render(fmt.Sprintf("   current: %s", truncateHash(current))))
			}
		}
	}

	fmt.Println(box("PCR Validation", pcrLines))

	if !pcrAllMatch {
		allMatch = false
	}

	// LUKS Token section
	if c.LUKSDevice != "" {
		var tokenLines []string

		token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice)
		if err != nil {
			tokenLines = append(tokenLines, errStyle.Render(fmt.Sprintf("✗ %v", err)))
			allMatch = false
		} else if token == nil {
			tokenLines = append(tokenLines, errStyle.Render("✗ No systemd-tpm2 token found"))
			allMatch = false
		} else {
			if token.NVIndex == 0 {
				tokenLines = append(tokenLines, warnStyle.Render("⚠ No NV index in token (standalone policy)"))
			} else if token.NVIndex != policy.NVIndex {
				tokenLines = append(tokenLines, errStyle.Render(
					fmt.Sprintf("✗ Wrong NV: token=0x%x policy=0x%x", token.NVIndex, policy.NVIndex)))
				allMatch = false
			} else {
				tokenLines = append(tokenLines, fmt.Sprintf("%s NV index matches policy (0x%x)", okStyle.Render("✓"), token.NVIndex))
			}

			if token.HasPCRLock {
				tokenLines = append(tokenLines, fmt.Sprintf("%s pcrlock enforced", okStyle.Render("✓")))
			} else {
				tokenLines = append(tokenLines, warnStyle.Render("⚠ pcrlock not enforced in token"))
			}
		}

		fmt.Println(box("LUKS Token", tokenLines))
	}

	fmt.Println()

	if !allMatch {
		return fmt.Errorf("verification failed")
	}

	return nil
}

func truncateHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "..."
	}
	return hash
}
