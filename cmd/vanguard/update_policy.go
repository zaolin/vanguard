package main

import (
	"fmt"
	"os"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

// Run executes the update-tpm-policy command
func (c *UpdatePolicyCmd) Run() error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Check UKI file exists
	if _, err := os.Stat(c.UKIPath); err != nil {
		return fmt.Errorf("UKI file not found: %s", c.UKIPath)
	}

	// Check pcrlock binary exists
	if _, err := os.Stat(pcrlock.PCRLockBin); err != nil {
		return fmt.Errorf("systemd-pcrlock not found at %s", pcrlock.PCRLockBin)
	}

	// Create bundle directory
	if err := os.MkdirAll(c.BundleDir, 0755); err != nil {
		return fmt.Errorf("failed to create bundle directory: %w", err)
	}

	// Phase 1: Configure PCR masks
	fmt.Println("[+] Configuring PCR masks...")
	if err := pcrlock.ConfigureMasks(); err != nil {
		return fmt.Errorf("failed to configure masks: %w", err)
	}

	// Phase 2: Lock PCRs
	fmt.Println("[+] Locking Secure Boot (PCR 7)...")
	if err := pcrlock.LockSecureBoot(); err != nil {
		return fmt.Errorf("failed to lock secure boot: %w", err)
	}

	fmt.Printf("[+] Locking UKI Measurement (PCR 4): %s\n", c.UKIPath)
	fmt.Println("    Using lock-pe with lock-uki fallback for reliable PCR4 prediction...")
	if err := pcrlock.LockUKIWithPEFallback(c.UKIPath); err != nil {
		return fmt.Errorf("failed to lock UKI: %w", err)
	}

	if c.LUKSDevice != "" {
		fmt.Printf("[+] Locking LUKS Header (PCR 8): %s\n", c.LUKSDevice)
		if err := pcrlock.LockLUKSHeader(c.LUKSDevice); err != nil {
			return fmt.Errorf("failed to lock LUKS header: %w", err)
		}
	}

	// Note: PCR 15 (machine-id, root-fs) is NOT locked because vanguard unlocks
	// LUKS before systemd extends PCR 15, causing a timing mismatch.
	// The PCR 15 pcrlock files are masked in ConfigureMasks().

	// Phase 3: Generate policy with recovery PIN
	fmt.Println("[+] Generating TPM policy...")
	fmt.Println("[+] Please enter your desired Recovery PIN when prompted below:")
	if err := pcrlock.MakePolicy(c.PolicyOutput); err != nil {
		return fmt.Errorf("failed to generate policy: %w", err)
	}

	// Verify if PCR 8 was included. systemd-pcrlock drops it if not found in event log.
	// Since we manually extend PCR 8, it won't be in the event log, so we must inject it.
	if c.LUKSDevice != "" {
		pcrs, err := pcrlock.Predict(c.PolicyOutput)
		if err == nil && !pcrs[8] {
			fmt.Println("[!] PCR 8 dropped by systemd-pcrlock (expected for manual extensions).")
			fmt.Println("[+] Manually injecting PCR 8 into policy...")
			if err := pcrlock.InjectPCR8(c.PolicyOutput); err != nil {
				return fmt.Errorf("failed to inject PCR 8: %w", err)
			}
		}
	}

	// Phase 4: Verification
	if !c.NoVerify {
		fmt.Println("[+] Verifying prediction...")
		// PCR 7 (secure boot) is required
		// PCR 4 (boot loader code) may be dropped by systemd-pcrlock if there are
		// unrecognized measurements (e.g., backup kernels)
		// PCR 15 is NOT included - vanguard unlocks before systemd extends it
		requiredPCRs := []int{7}

		// If LUKS device provided, PCR 8 is required
		if c.LUKSDevice != "" {
			requiredPCRs = append(requiredPCRs, 8)
		}

		if err := pcrlock.VerifyPolicy(c.PolicyOutput, requiredPCRs); err != nil {
			return fmt.Errorf("policy verification failed: %w", err)
		}

		// Check PCR status
		pcrs, _ := pcrlock.Predict(c.PolicyOutput)
		if pcrs[4] {
			fmt.Println("[+] PCR 4 (boot-loader-code) is active.")
		} else {
			fmt.Println("[!] Warning: PCR 4 (boot-loader-code) was dropped from policy.")
			fmt.Println("    This may happen if there are unrecognized boot entries (e.g., backup kernels).")
			fmt.Println("    The policy will still work but won't protect against boot loader changes.")
		}
		if pcrs[2] {
			fmt.Println("[+] PCR 2 (external-code) is active.")
		}
		if pcrs[3] {
			fmt.Println("[+] PCR 3 (external-config) is active.")
		}
		if pcrs[7] {
			fmt.Println("[+] PCR 7 (secure-boot-policy) is active.")
		}
		if pcrs[8] {
			fmt.Println("[+] PCR 8 (luks-header) is active.")
		}
	}

	fmt.Printf("[+] Success! Policy updated at %s\n", c.PolicyOutput)
	return nil
}
