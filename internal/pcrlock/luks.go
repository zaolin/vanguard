package pcrlock

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// LUKSTPMToken represents the systemd-tpm2 token data from a LUKS device
type LUKSTPMToken struct {
	Type       string `json:"type"`
	NVIndex    int    // Extracted from tpm2_pcrlock_nv blob
	PCRs       []int  `json:"tpm2-pcrs,omitempty"`
	HasPIN     bool   `json:"tpm2-pin,omitempty"`
	HasPCRLock bool   `json:"tpm2_pcrlock,omitempty"`
}

// GetLUKSTPMToken retrieves the TPM2 token information from a LUKS device
func GetLUKSTPMToken(devicePath string) (*LUKSTPMToken, error) {
	cmd := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", devicePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("luksDump failed: %w", err)
	}

	var dump struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(output, &dump); err != nil {
		return nil, fmt.Errorf("failed to parse LUKS dump: %w", err)
	}

	// Find systemd-tpm2 token
	for _, tokenData := range dump.Tokens {
		var token struct {
			Type       string `json:"type"`
			PCRs       []int  `json:"tpm2-pcrs,omitempty"`
			HasPIN     bool   `json:"tpm2-pin,omitempty"`
			HasPCRLock bool   `json:"tpm2_pcrlock,omitempty"`
			PCRLockNV  string `json:"tpm2_pcrlock_nv,omitempty"`
		}
		if err := json.Unmarshal(tokenData, &token); err != nil {
			continue
		}
		if token.Type == "systemd-tpm2" {
			tpmToken := &LUKSTPMToken{
				Type:       token.Type,
				PCRs:       token.PCRs,
				HasPIN:     token.HasPIN,
				HasPCRLock: token.HasPCRLock,
			}

			// Extract NV index from tpm2_pcrlock_nv blob if present
			if token.PCRLockNV != "" {
				nvIndex, err := extractNVIndexFromBlob(token.PCRLockNV)
				if err == nil {
					tpmToken.NVIndex = nvIndex
				}
			}

			return tpmToken, nil
		}
	}

	return nil, fmt.Errorf("no systemd-tpm2 token found on device")
}

// extractNVIndexFromBlob extracts the NV index from a base64-encoded TPM2B_NV_PUBLIC blob
// The NV index is stored as a 4-byte big-endian value at the start of the blob
func extractNVIndexFromBlob(b64 string) (int, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, fmt.Errorf("failed to decode base64: %w", err)
	}

	// The blob starts with a 2-byte size, then the TPMS_NV_PUBLIC structure
	// TPMS_NV_PUBLIC starts with TPMI_RH_NV_INDEX (4 bytes, the NV index)
	// However, systemd stores it slightly differently - the NV index appears
	// to be at offset 0 as a 4-byte big-endian value
	if len(data) < 4 {
		return 0, fmt.Errorf("blob too short")
	}

	// Read as big-endian 4-byte value
	nvIndex := binary.BigEndian.Uint32(data[0:4])
	return int(nvIndex), nil
}

// LockLUKSHeader locks PCR 8 for the LUKS header of the specified device.
// It uses cryptsetup luksHeaderBackup to get the header and systemd-pcrlock lock-raw to create the policy.
func LockLUKSHeader(devicePath string) error {
	stdout, stderr := cmdOutput()

	// 1. Dump LUKS header to temporary file
	tmpFile := filepath.Join(os.TempDir(), "luks-header.img")
	// Remove any existing file first (cryptsetup refuses to overwrite)
	os.Remove(tmpFile)
	// Make sure we clean up
	defer os.Remove(tmpFile)

	cmd := exec.Command("cryptsetup", "luksHeaderBackup", "--header-backup-file", tmpFile, devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksHeaderBackup failed: %v output: %s", err, string(output))
	}

	// 2. Generate pcrlock file using lock-raw on PCR 8
	// 800-luks-header.pcrlock seems appropriate (after 750-enter-initrd, before 830-root-fs)
	policyPath := filepath.Join(PCRLockDir, "800-luks-header.pcrlock")

	cmd = exec.Command(PCRLockBin, "lock-raw", "--pcr=8", fmt.Sprintf("--pcrlock=%s", policyPath), tmpFile)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-raw failed: %w", err)
	}

	return nil
}
