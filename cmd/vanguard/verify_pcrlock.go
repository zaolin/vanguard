package main

import (
	"fmt"
	"sort"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

type VerifyPCRLockCmd struct {
	PolicyPath string `short:"p" required:"" help:"Path to pcrlock.json policy file"`
	LUKSDevice string `short:"l" help:"Path to LUKS device to verify (optional)"`
}

func (c *VerifyPCRLockCmd) Run() error {
	policy, err := pcrlock.ParsePolicy(c.PolicyPath)
	if err != nil {
		return err
	}

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
