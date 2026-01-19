package pcrlock

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// LockLUKSHeader locks PCR 8 for the LUKS header of the specified device.
// It uses cryptsetup luksHeaderBackup to get the header and systemd-pcrlock lock-raw to create the policy.
func LockLUKSHeader(devicePath string) error {
	// 1. Dump LUKS header to temporary file
	tmpFile := filepath.Join(os.TempDir(), "luks-header.img")
	// Make sure we clean up
	defer os.Remove(tmpFile)

	fmt.Printf("[+] Dumping LUKS header from %s...\n", devicePath)
	cmd := exec.Command("cryptsetup", "luksHeaderBackup", "--header-backup-file", tmpFile, devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksHeaderBackup failed: %v output: %s", err, string(output))
	}

	// 2. Generate pcrlock file using lock-raw on PCR 8
	// 800-luks-header.pcrlock seems appropriate (after 750-enter-initrd, before 830-root-fs)
	policyPath := filepath.Join(PCRLockDir, "800-luks-header.pcrlock")

	fmt.Printf("[+] Generating PCR 8 policy for LUKS header...\n")
	cmd = exec.Command(PCRLockBin, "lock-raw", "--pcr=8", fmt.Sprintf("--pcrlock=%s", policyPath), tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-raw failed: %w", err)
	}

	return nil
}
