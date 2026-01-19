package luks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
)

// cryptsetupPaths contains possible locations for the cryptsetup binary
var cryptsetupPaths = []string{
	"/usr/bin/cryptsetup",
	"/usr/sbin/cryptsetup",
	"/sbin/cryptsetup",
	"/bin/cryptsetup",
}

// tpm2PcrextendPaths contains possible locations for the tpm2_pcrextend binary
var tpm2PcrextendPaths = []string{
	"/usr/bin/tpm2_pcrextend",
	"/bin/tpm2_pcrextend",
	"/usr/sbin/tpm2_pcrextend",
	"/sbin/tpm2_pcrextend",
}

// findBinary searches for a binary in the given paths
func findBinary(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// MeasureHeader extracts the LUKS header using cryptsetup luksHeaderBackup,
// calculates its SHA256 hash, and extends it into PCR 8.
func MeasureHeader(devicePath string) error {
	cryptsetup := findBinary(cryptsetupPaths)
	if cryptsetup == "" {
		return fmt.Errorf("cryptsetup binary not found")
	}

	// Create temp file for header backup (use /run since /tmp may not exist in initramfs)
	tmpFile := "/run/luks-header.img"
	defer os.Remove(tmpFile)

	// Use cryptsetup to dump the header correctly (handles offsets and sizes automatically)
	// cryptsetup luksHeaderBackup --header-backup-file <file> <device>
	cmd := exec.Command(cryptsetup, "luksHeaderBackup", "--header-backup-file", tmpFile, devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksHeaderBackup failed: %v output: %s", err, string(output))
	}

	// Read the backup file
	headerData, err := os.ReadFile(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to read header backup: %w", err)
	}

	// Calculate SHA256 hash
	hash := sha256.Sum256(headerData)
	hashHex := hex.EncodeToString(hash[:])

	// Note: Don't print to stdout as it interferes with TUI
	// Debug output is handled by the caller if needed

	// Extend PCR 8
	tpm2Pcrextend := findBinary(tpm2PcrextendPaths)
	if tpm2Pcrextend == "" {
		return fmt.Errorf("tpm2_pcrextend binary not found")
	}

	// tpm2_pcrextend 8:sha256=<hash>
	cmd = exec.Command(tpm2Pcrextend, fmt.Sprintf("8:sha256=%s", hashHex))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tpm2_pcrextend failed: %v output: %s", err, string(output))
	}

	return nil
}
