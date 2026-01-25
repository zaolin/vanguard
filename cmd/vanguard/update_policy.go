package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	fmt.Println("[1/5] Configuring PCR masks...")
	if err := pcrlock.ConfigureMasks(); err != nil {
		return fmt.Errorf("failed to configure masks: %w", err)
	}

	// Phase 2: Lock PCRs
	fmt.Println("[2/5] Locking PCR measurements...")
	if c.Verbose {
		fmt.Println("      Locking Secure Boot (PCR 7)...")
	}
	if err := pcrlock.LockSecureBoot(); err != nil {
		return fmt.Errorf("failed to lock secure boot: %w", err)
	}

	// Lock GPT partition table (PCR 5) - auto-enabled when LUKS device specified
	gptEnabled := c.LUKSDevice != "" && !c.NoGPT
	if gptEnabled {
		if c.Verbose {
			fmt.Println("      Locking GPT partition table (PCR 5)...")
		}
		// Derive the parent disk from the LUKS device (e.g., /dev/nvme0n1p2 -> /dev/nvme0n1)
		gptDevice := getParentDisk(c.LUKSDevice)
		if c.Verbose && gptDevice != "" {
			fmt.Printf("      Using disk: %s\n", gptDevice)
		}
		if err := pcrlock.LockGPT(gptDevice); err != nil {
			if err == pcrlock.ErrNoGPT {
				// Disk doesn't have GPT - skip GPT binding with a warning
				fmt.Println("      Note: Disk does not have GPT partition table, skipping PCR 5 binding")
				gptEnabled = false
				// Mask GPT pcrlock since we can't use it
				if err := pcrlock.MaskPolicy("600-gpt.pcrlock"); err != nil {
					return fmt.Errorf("failed to mask GPT policy: %w", err)
				}
			} else {
				return fmt.Errorf("failed to lock GPT: %w", err)
			}
		} else {
			// Also lock EFI action events (ExitBootServices) which are measured into PCR 5
			// These include both success and failure cases (failure happens on memory map changes)
			if c.Verbose {
				fmt.Println("      Locking EFI action events (PCR 5)...")
			}
			if err := pcrlock.LockEFIActions(); err != nil {
				return fmt.Errorf("failed to lock EFI actions: %w", err)
			}
		}
	} else {
		// Mask GPT pcrlock when not using LUKS device binding
		if err := pcrlock.MaskPolicy("600-gpt.pcrlock"); err != nil {
			return fmt.Errorf("failed to mask GPT policy: %w", err)
		}
	}

	if c.Verbose {
		fmt.Printf("      Locking UKI (PCR 4): %s\n", c.UKIPath)
	}
	if err := pcrlock.LockUKIWithPEFallback(c.UKIPath); err != nil {
		return fmt.Errorf("failed to lock UKI: %w", err)
	}

	// Phase 3: Generate policy with recovery PIN
	fmt.Println("[3/5] Generating TPM policy...")
	fmt.Println("      Enter Recovery PIN when prompted:")
	if err := pcrlock.MakePolicy(c.PolicyOutput); err != nil {
		return fmt.Errorf("failed to generate policy: %w", err)
	}

	// Phase 4: Verification and Summary
	fmt.Println("[4/5] Verifying policy...")

	if !c.NoVerify {
		// Require PCR 4 (boot loader) and PCR 7 (secure boot)
		requiredPCRs := []int{4, 7}

		if err := pcrlock.VerifyPolicy(c.PolicyOutput, requiredPCRs); err != nil {
			return fmt.Errorf("policy verification failed: %w", err)
		}

		// Check if GPT binding (PCR 5) was requested but not included
		if gptEnabled {
			pcrs, _ := pcrlock.Predict(c.PolicyOutput)
			if !pcrs[5] {
				fmt.Println("")
				fmt.Println("WARNING: GPT binding (PCR 5) was requested but not included in policy.")
				fmt.Println("         This typically happens when the firmware has additional PCR 5")
				fmt.Println("         events that systemd-pcrlock cannot predict (e.g., EFI errors).")
				fmt.Println("         Device identity validation via GPT will NOT be active.")
				gptEnabled = false
			}
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
				fmt.Printf("           --tpm2-with-pin=yes \\\n")
				fmt.Printf("           --tpm2-pcrlock=%s \\\n", c.PolicyOutput)
				fmt.Printf("           %s\n", c.LUKSDevice)
			}
		}
	}

	// Show active PCRs in pcrlock policy
	pcrs, _ := pcrlock.Predict(c.PolicyOutput)
	fmt.Print("Active PCRs:         ")
	first := true
	pcrNames := map[int]string{
		2: "external-code",
		3: "external-config",
		4: "boot-loader-code",
		5: "gpt-partition",
		7: "secure-boot",
	}
	for _, p := range []int{2, 3, 4, 5, 7} {
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
		fmt.Println("PCR Details (pcrlock policy):")
		for _, p := range []int{2, 3, 4, 5, 7} {
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

	// Show enrollment command if LUKS device specified
	if c.LUKSDevice != "" {
		fmt.Println("")
		fmt.Println("Enrollment Command")
		fmt.Println("==================")
		fmt.Printf("  systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto \\\n")
		fmt.Printf("    --tpm2-with-pin=yes \\\n")
		fmt.Printf("    --tpm2-pcrlock=%s \\\n", c.PolicyOutput)
		fmt.Printf("    %s\n", c.LUKSDevice)
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
	fmt.Println("")

	// Final Phase: Comprehensive Setup Verification
	fmt.Println("[5/5] Verifying Setup Integrity...")

	// Parse the newly created policy to verify against TPM
	newPolicy, err := pcrlock.ParsePolicy(c.PolicyOutput)
	if err != nil {
		fmt.Printf("⚠️  Failed to parse new policy for verification: %v\n", err)
	} else {
		// 1. Verify NV Index Sync
		_, nvMatch, err := pcrlock.VerifyNVIndex(newPolicy)
		if err != nil {
			fmt.Printf("   ❌ NV Index Check: Failed to read (%v)\n", err)
		} else if nvMatch {
			fmt.Println("✅ NV Index:       Synchronized (TPM matches policy)")
		} else {
			fmt.Println("❌ NV Index:       MISMATCH (TPM content differs from policy)")
			fmt.Println("Note: This is expected if you haven't run systemd-pcrlock make-policy yet,")
			fmt.Println("or if this is a fresh policy not yet written to NV index.")
		}

		// 2. Verify PCRs
		pcrMatches, currentValues, err := pcrlock.VerifyPCRs(newPolicy)
		if err != nil {
			fmt.Printf("❌ PCR Check:      Failed to read (%v)\n", err)
		} else {
			pcrFailures := 0
			for p, match := range pcrMatches {
				if !match {
					pcrFailures++
					fmt.Printf("  ❌ PCR %-2d:       MISMATCH (Current: %s)\n", p, currentValues[p])
				}
			}
			if pcrFailures == 0 {
				fmt.Println("✅ PCR Values:     Match Policy")
			} else {
				fmt.Println("❌ PCR Values:     MISMATCH (System state differs from policy)")
			}
		}
	}

	return nil
}

// getParentDisk extracts the parent disk device from a partition device path
// using /sys/block to handle all device types and naming schemes.
// For example: /dev/nvme0n1p2 -> /dev/nvme0n1, /dev/sda2 -> /dev/sda
func getParentDisk(devicePath string) string {
	// Resolve symlinks to get the real device path
	realPath, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		realPath = devicePath
	}

	// Extract device name from path (e.g., /dev/nvme0n1p2 -> nvme0n1p2)
	devName := filepath.Base(realPath)

	// Check if this device has a parent in /sys/block/*/devName
	// For partitions, the structure is: /sys/block/<disk>/<partition>
	sysBlockPath := "/sys/block"
	entries, err := os.ReadDir(sysBlockPath)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		diskName := entry.Name()
		// Check if our device is a partition of this disk
		partPath := filepath.Join(sysBlockPath, diskName, devName)
		if _, err := os.Stat(partPath); err == nil {
			// Found the parent disk
			return "/dev/" + diskName
		}
	}

	// Device might be a whole disk itself, or couldn't find parent
	// Return empty to let systemd-pcrlock auto-detect
	return ""
}
