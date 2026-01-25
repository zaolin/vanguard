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
	// 1. Load Policy
	pcrlockPolicy, err := pcrlock.ParsePolicy(c.PolicyPath)
	if err != nil {
		return err
	}

	fmt.Println("PCRLock Setup Verification")
	fmt.Println("==========================")
	fmt.Printf("Policy File: %s\n", c.PolicyPath)
	fmt.Printf("NV Index:    0x%x\n", pcrlockPolicy.NVIndex)
	fmt.Println()

	var allMatch bool = true

	// 2. NV Index Validation (The "Sync" Check)
	fmt.Println("1. NV Index Synchronization")
	fmt.Println("---------------------------")

	nvDetails, nvMatch, err := pcrlock.VerifyNVIndex(pcrlockPolicy)
	if err != nil {
		fmt.Printf("❌ Failed to read NV Index 0x%x: %v\n", pcrlockPolicy.NVIndex, err)
		fmt.Println("   (Ensure you are running as root and TPM is accessible)")
		allMatch = false
	} else {
		// We have details, let's print them
		// Re-extract expectation for display purposes if needed,
		// but VerifyNVIndex already did the check.
		// For detailed output we might want to manually check again or just trust the boolean.
		// To match previous detailed output, let's re-implement the display logic but use the details.

		// Parse policy expectations again just for display
		// (VerifyNVIndex does this internally but doesn't return the expected string)
		// We can just rely on the boolean match for simplicity or parse it if we want to show diffs.
		// The original code showed "Expected vs Actual".
		// Let's assume VerifyNVIndex is correct, but for the CLI tool we want verbose diffs.
		// Actually, let's just use the boolean for now to simplify, or maybe I should have made VerifyNVIndex return expected values too.
		// It returns `nvDetails`.

		if nvMatch {
			fmt.Printf("✅ Auth Policy matches: %s\n", truncateHash(nvDetails.AuthPolicy))
			fmt.Printf("✅ NV Size matches: %d bytes\n", nvDetails.Size)
			fmt.Println("✅ NV Index fully matches policy file (TPM is in sync)")
		} else {
			fmt.Printf("❌ NV Index MISMATCH!\n")
			// To show expected values we need to parse nvPublic again here locally
			// or change VerifyNVIndex to return them.
			// Let's keep it simple and just say it mismatched for now,
			// or quickly re-parse since we have the policy.
			// Re-parsing is cheap.

			// We can't access extractNVPublicDetails since it is unexported in pcrlock.
			// That is a slight oversight in my plan if I wanted identical output.
			// However, checking the mismatch is the most important part.
			fmt.Printf("   Actual Auth: %s\n", nvDetails.AuthPolicy)
			fmt.Printf("   Actual Size: %d\n", nvDetails.Size)
			fmt.Println("❌ NV Index out of sync - run 'vanguard update-tpm-policy'")
			allMatch = false
		}
	}
	fmt.Println()

	// 2. Current PCR Validation
	fmt.Println("2. Current PCR Validation")
	fmt.Println("-------------------------")

	pcrMatches, currentValues, err := pcrlock.VerifyPCRs(pcrlockPolicy)
	if err != nil {
		return fmt.Errorf("failed to read PCRs: %w", err)
	}

	// Sort PCRs for display
	var requiredPCRs []int
	for _, pv := range pcrlockPolicy.PCRValues {
		requiredPCRs = append(requiredPCRs, pv.PCR)
	}
	sort.Ints(requiredPCRs)

	pcrOverallMatch := true
	for _, pcr := range requiredPCRs {
		name := pcrlock.PCRNames[pcr]
		if name == "" {
			name = "unknown"
		}

		matched := pcrMatches[pcr]
		current := currentValues[pcr]

		if matched {
			fmt.Printf("✅ PCR %-2d (%s): OK\n", pcr, name)
		} else {
			fmt.Printf("❌ PCR %-2d (%s): MISMATCH\n", pcr, name)
			fmt.Printf("   Current: %s\n", current)

			// Find allowed values for this PCR
			for _, pv := range pcrlockPolicy.PCRValues {
				if pv.PCR == pcr {
					if len(pv.Values) == 1 {
						fmt.Printf("   Allowed: %s\n", pv.Values[0])
					} else {
						fmt.Printf("   Allowed: %d variants (none match)\n", len(pv.Values))
					}
					break
				}
			}
			pcrOverallMatch = false
		}
	}
	fmt.Println()

	// 4. LUKS Token and Header Validation
	if c.LUKSDevice != "" {
		fmt.Println("3. LUKS Token Validation")
		fmt.Println("------------------------")
		token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice)
		if err != nil {
			fmt.Printf("❌ LUKS Validation Failed: %v\n", err)
		} else {
			if token == nil {
				fmt.Println("❌ No systemd-tpm2 token found on device")
			} else {
				// Verify NV Index
				if token.NVIndex == 0 {
					fmt.Println("❌ LUKS token does not reference an NV Index (likely standalone policy?)")
				} else if token.NVIndex != pcrlockPolicy.NVIndex {
					fmt.Printf("❌ LUKS token references WRONG NV Index: 0x%x (Policy uses 0x%x)\n", token.NVIndex, pcrlockPolicy.NVIndex)
					fmt.Println("   This means the LUKS slot is bound to a different policy chain.")
				} else {
					fmt.Printf("✅ LUKS token references correct NV Index (0x%x)\n", token.NVIndex)
				}

				// Warn if pcrlock check is disabled
				if !token.HasPCRLock {
					fmt.Println("⚠️  LUKS token does NOT enforce pcrlock (tpm2-pcrlock=true missing)")
				} else {
					fmt.Println("✅ LUKS token enforces pcrlock")
				}
			}
		}
		fmt.Println()
	}

	if !allMatch || !pcrOverallMatch {
		return fmt.Errorf("verification failed: NV Index or PCR mismatch detected")
	}

	return nil
}

// truncateHash returns first 16 chars of a hash for display
func truncateHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "..."
	}
	return hash
}
