package main

import (
	"fmt"
	"os"
	"os/exec"
)

// EnrollCmd wraps the systemd-cryptenroll + vanguard update workflow.
// It runs 'vanguard update' first to generate a fresh pcrlock policy,
// then calls systemd-cryptenroll to enroll the TPM2 token on the LUKS device.
type EnrollCmd struct {
	UKIPath    string `short:"u" required:"" help:"Path to UKI file (e.g., /boot/EFI/Gentoo/kernel.efi)"`
	LUKSDevice string `short:"l" required:"" help:"LUKS device to enroll (e.g., /dev/nvme0n1p2)"`
	WithPIN    bool   `short:"p" help:"Require PIN for TPM2 unseal (recommended)"`
	Verbose    bool   `short:"v" help:"Show verbose output"`
}

func (c *EnrollCmd) Run() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	if _, err := os.Stat(c.UKIPath); err != nil {
		return fmt.Errorf("UKI file not found: %s", c.UKIPath)
	}

	if _, err := os.Stat(c.LUKSDevice); err != nil {
		return fmt.Errorf("LUKS device not found: %s", c.LUKSDevice)
	}

	// Check systemd-cryptenroll exists
	cryptenroll, err := exec.LookPath("systemd-cryptenroll")
	if err != nil {
		return fmt.Errorf("systemd-cryptenroll not found — install systemd with cryptsetup support")
	}

	// Step 1: Generate pcrlock policy
	fmt.Println()
	fmt.Println("  " + headerSty.Render("STEP 1: Generate PCRLock Policy"))
	fmt.Println()

	policyPath := c.UKIPath
	if len(policyPath) > 4 && policyPath[len(policyPath)-4:] == ".efi" {
		policyPath = policyPath[:len(policyPath)-4]
	} else if len(policyPath) > 4 {
		lower := policyPath[len(policyPath)-4:]
		if lower == ".EFI" {
			policyPath = policyPath[:len(policyPath)-4]
		}
	}
	policyPath += ".pcrlock.json"

	updateArgs := []string{"vanguard", "update", "-u", c.UKIPath, "-l", c.LUKSDevice, "-p", policyPath}
	if c.Verbose {
		updateArgs = append(updateArgs, "-V")
	}

	fmt.Printf("  Running: %s\n", updateArgs[1])
	fmt.Println()
	// We can't call the subcommand directly, so exec ourselves
	updateCmd := exec.Command(os.Args[0], updateArgs[1:]...)
	updateCmd.Stdin = os.Stdin
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate policy: %w", err)
	}

	// Step 2: Enroll TPM2 token
	fmt.Println()
	fmt.Println("  " + headerSty.Render("STEP 2: Enroll TPM2 Token"))
	fmt.Println()

	enrollArgs := []string{
		"--wipe-slot=tpm2",
		"--tpm2-device=auto",
	}
	if c.WithPIN {
		enrollArgs = append(enrollArgs, "--tpm2-with-pin=yes")
	}
	enrollArgs = append(enrollArgs, "--tpm2-pcrlock="+policyPath, c.LUKSDevice)

	fmt.Printf("  Running: systemd-cryptenroll %s\n", policyPath)
	fmt.Println()

	enrollCmd := exec.Command(cryptenroll, enrollArgs...)
	enrollCmd.Stdin = os.Stdin
	enrollCmd.Stdout = os.Stdout
	enrollCmd.Stderr = os.Stderr
	if err := enrollCmd.Run(); err != nil {
		return fmt.Errorf("systemd-cryptenroll failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %s TPM2 token enrolled successfully on %s\n", okStyle.Render("✓"), c.LUKSDevice)
	fmt.Printf("  Policy: %s\n", policyPath)
	fmt.Println()
	fmt.Printf("  %s Tip: run 'vanguard recovery --enable' to set up TOTP recovery\n",
		dimStyle.Render("•"))
	fmt.Println()

	return nil
}
