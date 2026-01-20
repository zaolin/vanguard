package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

// Run executes the update-tpm-policy command
func (c *UpdatePolicyCmd) Run() error {
	// Set verbose mode for pcrlock package
	pcrlock.Verbose = c.Verbose

	// Check for root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Check UKI file exists
	if _, err := os.Stat(c.UKIPath); err != nil {
		return fmt.Errorf("UKI file not found: %s", c.UKIPath)
	}

	// Derive policy output path from UKI path if not specified
	// /boot/EFI/Gentoo/kernel.efi -> /boot/EFI/Gentoo/kernel.pcrlock.json
	if c.PolicyOutput == "" {
		c.PolicyOutput = strings.TrimSuffix(c.UKIPath, ".efi") + ".pcrlock.json"
	}

	// Check pcrlock binary exists
	if _, err := os.Stat(pcrlock.PCRLockBin); err != nil {
		return fmt.Errorf("systemd-pcrlock not found at %s", pcrlock.PCRLockBin)
	}

	// Phase 1: Configure PCR masks
	fmt.Println("[1/4] Configuring PCR masks...")
	if err := pcrlock.ConfigureMasks(); err != nil {
		return fmt.Errorf("failed to configure masks: %w", err)
	}

	// Phase 2: Lock PCRs
	fmt.Println("[2/4] Locking PCR measurements...")
	if c.Verbose {
		fmt.Println("      Locking Secure Boot (PCR 7)...")
	}
	if err := pcrlock.LockSecureBoot(); err != nil {
		return fmt.Errorf("failed to lock secure boot: %w", err)
	}

	if c.Verbose {
		fmt.Printf("      Locking UKI (PCR 4): %s\n", c.UKIPath)
	}
	if err := pcrlock.LockUKIWithPEFallback(c.UKIPath); err != nil {
		return fmt.Errorf("failed to lock UKI: %w", err)
	}

	if c.LUKSDevice != "" {
		if c.Verbose {
			fmt.Printf("      Locking LUKS Header (PCR 8): %s\n", c.LUKSDevice)
		}
		if err := pcrlock.LockLUKSHeader(c.LUKSDevice); err != nil {
			return fmt.Errorf("failed to lock LUKS header: %w", err)
		}
	}

	// Phase 3: Generate policy with recovery PIN
	fmt.Println("[3/4] Generating TPM policy...")
	fmt.Println("      Enter Recovery PIN when prompted:")
	if err := pcrlock.MakePolicy(c.PolicyOutput); err != nil {
		return fmt.Errorf("failed to generate policy: %w", err)
	}

	// Inject PCR 8 if needed (systemd-pcrlock drops it if not in event log)
	if c.LUKSDevice != "" {
		pcrs, err := pcrlock.Predict(c.PolicyOutput)
		if err == nil && !pcrs[8] {
			if c.Verbose {
				fmt.Println("      Injecting PCR 8 (not in event log)...")
			}
			if err := pcrlock.InjectPCR8(c.PolicyOutput); err != nil {
				return fmt.Errorf("failed to inject PCR 8: %w", err)
			}
		}
	}

	// Phase 4: Verification and Summary
	fmt.Println("[4/4] Verifying policy...")

	if !c.NoVerify {
		requiredPCRs := []int{7}
		if c.LUKSDevice != "" {
			requiredPCRs = append(requiredPCRs, 8)
		}

		if err := pcrlock.VerifyPolicy(c.PolicyOutput, requiredPCRs); err != nil {
			return fmt.Errorf("policy verification failed: %w", err)
		}
	}

	// Print summary
	fmt.Println("")
	fmt.Println("Policy Summary")
	fmt.Println("==============")

	// Get policy NV index
	policyNVIndex, err := pcrlock.GetPolicyNVIndex(c.PolicyOutput)
	if err != nil {
		return fmt.Errorf("failed to read policy NV index: %w", err)
	}
	fmt.Printf("Policy NV Index:     0x%x\n", policyNVIndex)

	// Check LUKS token NV index if device provided
	if c.LUKSDevice != "" {
		token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice)
		if err != nil {
			fmt.Printf("LUKS Token NV Index: (not found: %v)\n", err)
		} else {
			fmt.Printf("LUKS Token NV Index: 0x%x\n", token.NVIndex)

			if token.NVIndex == policyNVIndex {
				fmt.Println("NV Index Match:      YES")
			} else {
				fmt.Println("NV Index Match:      NO (policy will not work!)")
				fmt.Println("")
				fmt.Println("WARNING: The LUKS token points to a different NV index.")
				fmt.Println("         You need to re-enroll the TPM token with:")
				fmt.Printf("         systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto \\\n")
				fmt.Printf("           --tpm2-with-pin=yes --tpm2-pcrlock=%s %s\n", c.PolicyOutput, c.LUKSDevice)
			}
		}
	}

	// Show active PCRs
	pcrs, _ := pcrlock.Predict(c.PolicyOutput)
	fmt.Print("Active PCRs:         ")
	first := true
	pcrNames := map[int]string{
		2: "external-code",
		3: "external-config",
		4: "boot-loader-code",
		7: "secure-boot",
		8: "luks-header",
	}
	for _, p := range []int{2, 3, 4, 7, 8} {
		if pcrs[p] {
			if !first {
				fmt.Print(", ")
			}
			fmt.Printf("%d", p)
			first = false
		}
	}
	fmt.Println("")

	// Show PCR details in verbose mode
	if c.Verbose {
		fmt.Println("")
		fmt.Println("PCR Details:")
		for _, p := range []int{2, 3, 4, 7, 8} {
			status := "inactive"
			if pcrs[p] {
				status = "active"
			}
			name := pcrNames[p]
			if name == "" {
				name = "unknown"
			}
			fmt.Printf("  PCR %2d (%s): %s\n", p, name, status)
		}
	}

	// Warnings for missing PCRs
	if !pcrs[4] {
		fmt.Println("")
		fmt.Println("NOTE: PCR 4 (boot-loader-code) not in policy.")
		fmt.Println("      This may happen with unrecognized boot entries.")
	}

	// Cleanup old NV indices if requested
	if c.Cleanup {
		fmt.Println("")
		fmt.Println("Cleaning up old NV indices...")

		// Collect indices to keep: current policy and LUKS token (if different)
		keepIndices := []int{policyNVIndex}
		if c.LUKSDevice != "" {
			if token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice); err == nil && token.NVIndex != 0 {
				if token.NVIndex != policyNVIndex {
					keepIndices = append(keepIndices, token.NVIndex)
				}
			}
		}

		removed, err := pcrlock.CleanupOldNVIndices(keepIndices)
		if err != nil {
			fmt.Printf("Warning: cleanup failed: %v\n", err)
		} else if removed > 0 {
			fmt.Printf("Removed %d old NV index(es)\n", removed)
		} else {
			fmt.Println("No old NV indices to remove")
		}
	}

	fmt.Println("")
	fmt.Printf("Policy written to: %s\n", c.PolicyOutput)

	return nil
}
