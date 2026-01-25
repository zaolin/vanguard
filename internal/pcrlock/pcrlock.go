package pcrlock

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// PCRLockBin is the path to the systemd-pcrlock binary
	PCRLockBin = "/usr/lib/systemd/systemd-pcrlock"
	// PCRLockDir is the directory for pcrlock policy files
	PCRLockDir = "/etc/pcrlock.d"

	// NV index range used by systemd-pcrlock (owner hierarchy, ordinary index)
	// These are in the range 0x01800000 - 0x01BFFFFF (TPM_HT_NV_INDEX | TPM_RH_OWNER)
	nvIndexMin = 0x01800000
	nvIndexMax = 0x01BFFFFF
)

// Verbose controls whether command output is shown
var Verbose bool

// cmdOutput returns the appropriate stdout/stderr writers based on Verbose setting
func cmdOutput() (io.Writer, io.Writer) {
	if Verbose {
		return os.Stdout, os.Stderr
	}
	return io.Discard, io.Discard
}

// Masked policies - noisy/unsupported PCRs that change frequently
// PCR 15 policies are masked because vanguard unlocks LUKS before systemd
// extends PCR 15, causing a timing mismatch with pcrlock predictions
// Note: 600-gpt.pcrlock is NOT masked by default - it's conditionally masked
// in update_policy.go based on whether --luks-device is specified
var maskedPolicies = []string{
	"200-firmware-code.pcrlock",
	"220-firmware-config.pcrlock",
	"250-firmware-code-early.pcrlock",
	"250-firmware-config-early.pcrlock",
	"750-enter-initrd.pcrlock",
	"800-leave-initrd.pcrlock",
	"820-machine-id.pcrlock",
	"830-root-file-system.pcrlock",
	"850-sysinit.pcrlock",
	"900-ready.pcrlock",
	"940-machine-id.pcrlock",
	"940-machine-id-null.pcrlock",
	"950-root-file-system.pcrlock",
	"950-root-file-system-null.pcrlock",
	"950-shutdown.pcrlock",
	"990-final.pcrlock",
}

// Unmasked policies - safe/stable PCRs (2, 3)
var unmaskedPolicies = []string{
	"400-external-code.pcrlock",
	"400-external-config.pcrlock",
}

// Stale locks to remove before regenerating
var staleLocks = []string{
	"240-secureboot-policy.pcrlock",
	"620-secureboot-authority.pcrlock",
	// Remove PCR 15 locks that may have been created by previous versions
	"940-machine-id.pcrlock",
	"940-machine-id-null.pcrlock",
	"950-root-file-system.pcrlock",
	"950-root-file-system-null.pcrlock",
	// Remove old 100-uki directory (renamed to 510-uki for correct PCR 4 ordering)
	"100-uki.pcrlock.d",
	"100-uki.pcrlock",
}

// MaskPolicy creates a symlink to /dev/null for a policy file
func MaskPolicy(name string) error {
	path := filepath.Join(PCRLockDir, name)

	// Check if already a symlink to /dev/null
	if target, err := os.Readlink(path); err == nil && target == "/dev/null" {
		return nil
	}

	// Remove existing file if present
	os.Remove(path)

	return os.Symlink("/dev/null", path)
}

// UnmaskPolicy removes a mask symlink
func UnmaskPolicy(name string) error {
	path := filepath.Join(PCRLockDir, name)

	// Only remove if it's a symlink
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return os.Remove(path)
		}
	}
	return nil
}

// RemoveStaleLocks removes old/stale lock files
func RemoveStaleLocks() error {
	for _, name := range staleLocks {
		path := filepath.Join(PCRLockDir, name)
		// Use RemoveAll to handle both files and directories
		os.RemoveAll(path) // Ignore errors - file/dir may not exist
	}
	return nil
}

// ConfigureMasks sets up all policy masks
func ConfigureMasks() error {
	// Create pcrlock.d directory if needed
	if err := os.MkdirAll(PCRLockDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", PCRLockDir, err)
	}

	// Remove stale locks
	RemoveStaleLocks()

	// Mask noisy policies
	for _, name := range maskedPolicies {
		if err := MaskPolicy(name); err != nil {
			return fmt.Errorf("failed to mask %s: %w", name, err)
		}
	}

	// Unmask safe policies
	for _, name := range unmaskedPolicies {
		if err := UnmaskPolicy(name); err != nil {
			return fmt.Errorf("failed to unmask %s: %w", name, err)
		}
	}

	return nil
}

// LockSecureBoot locks PCR 7 (policy + authority)
func LockSecureBoot() error {
	stdout, stderr := cmdOutput()

	// Lock secureboot policy
	cmd := exec.Command(PCRLockBin, "lock-secureboot-policy")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-secureboot-policy failed: %w", err)
	}

	// Lock secureboot authority
	cmd = exec.Command(PCRLockBin, "lock-secureboot-authority")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-secureboot-authority failed: %w", err)
	}

	return nil
}

// ErrNoGPT is returned when the disk doesn't have a GPT partition table
var ErrNoGPT = fmt.Errorf("disk does not have GPT partition table")

// LockEFIActions adds a variant to handle EFI ExitBootServices retry scenarios.
// The standard systemd pcrlock at /usr/lib/pcrlock.d/700-action-efi-exit-boot-services.pcrlock.d
// only covers direct success (Invocation → Success), but some systems retry after failure:
// Invocation → Failure → Invocation → Success
// We add a variant to /etc/pcrlock.d to cover this case.
func LockEFIActions() error {
	// Add variant to /etc/pcrlock.d with same component name
	variantDir := filepath.Join(PCRLockDir, "700-action-efi-exit-boot-services.pcrlock.d")

	// Clean up old locations
	os.RemoveAll(filepath.Join(PCRLockDir, "550-efi-actions.pcrlock.d"))
	os.Remove(filepath.Join(PCRLockDir, "550-efi-actions.pcrlock"))

	// Create variant directory
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create efi-actions variant directory: %w", err)
	}

	// EFI action strings - must match exactly what firmware measures
	invocation := "Exit Boot Services Invocation"
	success := "Exit Boot Services Returned with Success"
	failure := "Exit Boot Services Returned with Failure"

	// Helper to create a record
	makeRecord := func(action string) map[string]interface{} {
		sha256Hash := sha256.Sum256([]byte(action))
		return map[string]interface{}{
			"pcr": 5,
			"digests": []map[string]interface{}{
				{
					"hashAlg": "sha256",
					"digest":  fmt.Sprintf("%x", sha256Hash[:]),
				},
			},
		}
	}

	// Variant: With retry - some firmware logs: Failure → Invocation → Success
	// (The first Invocation is missing from the log, only the retry sequence appears)
	withRetry := map[string]interface{}{
		"records": []map[string]interface{}{
			makeRecord(failure),
			makeRecord(invocation),
			makeRecord(success),
		},
	}

	// Write the retry variant
	data, err := json.MarshalIndent(withRetry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal with-retry pcrlock: %w", err)
	}
	// Use 350- prefix to be tried before 600-absent but in same selection as 300-present
	if err := os.WriteFile(filepath.Join(variantDir, "350-with-retry.pcrlock"), data, 0644); err != nil {
		return fmt.Errorf("failed to write with-retry pcrlock: %w", err)
	}

	return nil
}

// LockGPT creates a pcrlock file for the GPT partition table (PCR 5).
// This binds the policy to the specific disk's partition layout, providing
// device identity validation. The measurement is done by firmware and is
// already in the UEFI event log before the initramfs runs.
// If device is empty, systemd-pcrlock will auto-detect the boot device.
// Returns ErrNoGPT if the disk doesn't have a GPT partition table.
func LockGPT(device string) error {
	args := []string{"lock-gpt"}
	if device != "" {
		args = append(args, device)
	}
	cmd := exec.Command(PCRLockBin, args...)

	if Verbose {
		// In verbose mode, we still need to capture output to detect GPT errors
		output, err := cmd.CombinedOutput()
		if err != nil {
			outputStr := string(output)
			// Print output for verbose mode
			fmt.Print(outputStr)
			if strings.Contains(outputStr, "does not have GPT partition table") {
				return ErrNoGPT
			}
			return fmt.Errorf("lock-gpt failed: %w", err)
		}
		fmt.Print(string(output))
	} else {
		// Capture stderr for error reporting even in non-verbose mode
		output, err := cmd.CombinedOutput()
		if err != nil {
			outputStr := strings.TrimSpace(string(output))
			if strings.Contains(outputStr, "does not have GPT partition table") {
				return ErrNoGPT
			}
			return fmt.Errorf("lock-gpt failed: %w: %s", err, outputStr)
		}
	}
	return nil
}

// LockUKI locks PCR 4 for the given UKI path (single file mode)
func LockUKI(ukiPath string) error {
	stdout, stderr := cmdOutput()
	cmd := exec.Command(PCRLockBin, "lock-uki", ukiPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-uki failed: %w", err)
	}
	return nil
}

// LockUKIVariant locks PCR 4 for the given UKI path into a variant directory
// This creates /etc/pcrlock.d/510-uki.pcrlock.d/<name>.pcrlock
// The 510 prefix ensures UKI comes after firmware PCR 4 events:
// - 350-action-efi-application (EV_EFI_ACTION)
// - 500-separator (EV_SEPARATOR)
// Using variants allows both old (currently booted) and new UKI to be valid
func LockUKIVariant(ukiPath string, variantName string) error {
	stdout, stderr := cmdOutput()
	variantDir := filepath.Join(PCRLockDir, "510-uki.pcrlock.d")
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	pcrLockPath := filepath.Join(variantDir, variantName+".pcrlock")

	cmd := exec.Command(PCRLockBin, "lock-uki", ukiPath, "--pcrlock="+pcrLockPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-uki variant failed: %w", err)
	}
	return nil
}

// LockUKIWithVariants creates UKI variant for the new UKI file
// This allows the policy to work with both currently booted UKI and the new one
func LockUKIWithVariants(newUKIPath string) error {
	stdout, stderr := cmdOutput()
	variantDir := filepath.Join(PCRLockDir, "510-uki.pcrlock.d")

	// Remove old single-file pcrlock if exists (we're switching to variant directory)
	os.Remove(filepath.Join(PCRLockDir, "510-uki.pcrlock"))

	// Create variant directory
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	// Create new variant from specified UKI file
	newPath := filepath.Join(variantDir, "new.pcrlock")
	cmd := exec.Command(PCRLockBin, "lock-uki", newUKIPath, "--pcrlock="+newPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to lock new UKI: %w", err)
	}

	return nil
}

// LockMachineID locks PCR 15 for machine ID
func LockMachineID() error {
	stdout, stderr := cmdOutput()
	cmd := exec.Command(PCRLockBin, "lock-machine-id")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-machine-id failed: %w", err)
	}
	return nil
}

// LockFileSystem locks PCR 15 for root filesystem
func LockFileSystem(path string) error {
	stdout, stderr := cmdOutput()
	cmd := exec.Command(PCRLockBin, "lock-file-system", path)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-file-system failed: %w", err)
	}
	return nil
}

// MakePolicy generates policy with recovery PIN prompt
func MakePolicy(outputPath string) error {
	stdout, stderr := cmdOutput()

	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Try to reuse existing NV index to prevent exhaustion
	var nvIndexArgs []string
	if data, err := os.ReadFile(outputPath); err == nil {
		// Use a simple struct to extract just the NV index
		type nvInfo struct {
			NVIndex int `json:"nvIndex"`
		}
		var info nvInfo
		if err := json.Unmarshal(data, &info); err == nil && info.NVIndex != 0 {
			nvIndexArgs = []string{fmt.Sprintf("--nv-index=0x%x", info.NVIndex)}
			if Verbose {
				fmt.Printf("[+] Reusing existing NV Index: 0x%x\n", info.NVIndex)
			}

			// We MUST undefine the existing index because systemd-pcrlock make-policy
			// tries to define it anew and fails if it exists.
			// This effectively "reuses" the slot by freeing it up first.
			// We use tpm2_nvundefine for this.
			undefCmd := exec.Command("tpm2_nvundefine", fmt.Sprintf("0x%x", info.NVIndex))
			// Ignore output/error - if it fails (e.g. doesn't exist), make-policy will handle it
			_ = undefCmd.Run()
		}
	}

	// Remove existing policy file (required by make-policy to overwrite)
	os.Remove(outputPath)

	args := []string{"make-policy", "--policy=" + outputPath, "--force", "--recovery-pin=query"}
	// Add --quiet flag when not in verbose mode to suppress diagnostic output
	if !Verbose {
		args = append(args, "--quiet")
	}
	args = append(args, nvIndexArgs...)

	cmd := exec.Command(PCRLockBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make-policy failed: %w", err)
	}
	return nil
}

// Predict reads the policy file and returns which PCRs are active.
// It parses the JSON directly.
func Predict(policyPath string) (map[int]bool, error) {
	policyJSON, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	policyInfo, err := ParsePolicyJSON(policyJSON)
	if err != nil {
		return nil, err
	}

	pcrs := make(map[int]bool)
	for _, pcr := range policyInfo.PCRs {
		pcrs[pcr] = true
	}

	return pcrs, nil
}

// VerifyPolicy checks that required PCRs are present in the policy.
// It parses the policy JSON directly to verify presence, as systemd-pcrlock
// might filter out PCRs it doesn't recognize from the event log.
func VerifyPolicy(policyPath string, requiredPCRs []int) error {
	policyJSON, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	policyInfo, err := ParsePolicyJSON(policyJSON)
	if err != nil {
		return err
	}

	presentPCRs := make(map[int]bool)
	for _, pcr := range policyInfo.PCRs {
		presentPCRs[pcr] = true
	}

	for _, pcr := range requiredPCRs {
		if !presentPCRs[pcr] {
			return fmt.Errorf("PCR %d missing from policy", pcr)
		}
	}

	return nil
}

// PredictJSON returns the raw JSON prediction output
func PredictJSON(policyPath string) ([]byte, error) {
	cmd := exec.Command(PCRLockBin, "predict",
		"--policy="+policyPath,
		"--json=pretty",
	)
	return cmd.Output()
}

// PolicyInfo contains parsed policy information
type PolicyInfo struct {
	PCRs    []int
	NVIndex int
}

type policyEntry struct {
	PCR int `json:"pcr"`
}

// GetPolicyNVIndex reads the NV index from a policy file
func GetPolicyNVIndex(policyPath string) (int, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read policy: %w", err)
	}

	var policy struct {
		NVIndex int `json:"nvIndex"`
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return 0, fmt.Errorf("failed to parse policy: %w", err)
	}

	return policy.NVIndex, nil
}

// ParsePolicyJSON parses JSON policy data.
// It handles two formats:
// 1. Array of objects (from systemd-pcrlock predict --json=pretty)
// 2. Object with "pcrValues" field (from pcrlock.json file)
func ParsePolicyJSON(data []byte) (*PolicyInfo, error) {
	// Trim whitespace to check first char
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty policy data")
	}

	info := &PolicyInfo{}

	// Case 1: Object format (start with '{')
	if trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(data, &rawMap); err != nil {
			return nil, fmt.Errorf("failed to parse policy object map: %w", err)
		}
		if val, ok := rawMap["pcrValues"]; ok {
			var entries []policyEntry
			if err := json.Unmarshal(val, &entries); err != nil {
				return nil, fmt.Errorf("failed to parse pcrValues: %w", err)
			}
			for _, e := range entries {
				info.PCRs = append(info.PCRs, e.PCR)
			}
			return info, nil
		}
		return info, nil
	}

	// Case 2: Array format (start with '[')
	if trimmed[0] == '[' {
		var resultArray []map[string]interface{}
		if err := json.Unmarshal(data, &resultArray); err != nil {
			return nil, fmt.Errorf("failed to parse policy array: %w", err)
		}

		seen := make(map[int]bool)
		for _, entry := range resultArray {
			if pcr, ok := entry["pcr"].(float64); ok {
				p := int(pcr)
				if !seen[p] {
					seen[p] = true
					info.PCRs = append(info.PCRs, p)
				}
			}
		}
		return info, nil
	}

	return nil, fmt.Errorf("unknown JSON format")
}

// LockPE locks PCR 4 for the given PE binary using lock-pe
// This is more reliable than lock-uki for PCR4 measurements when sd-stub uses LoadImage
func LockPE(pePath string) error {
	stdout, stderr := cmdOutput()
	cmd := exec.Command(PCRLockBin, "lock-pe", pePath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-pe failed: %w", err)
	}
	return nil
}

// LockPEVariant locks PCR 4 for PE binary into variant directory
func LockPEVariant(pePath string, variantName string) error {
	stdout, stderr := cmdOutput()
	variantDir := filepath.Join(PCRLockDir, "510-uki.pcrlock.d")
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	pcrLockPath := filepath.Join(variantDir, variantName+".pcrlock")
	cmd := exec.Command(PCRLockBin, "lock-pe", pePath, "--pcrlock="+pcrLockPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-pe variant failed: %w", err)
	}
	return nil
}

// LockUKIWithPEFallback creates both lock-pe and lock-uki predictions as variants
// lock-pe is primary (more reliable for PCR4 when sd-stub uses LoadImage)
// lock-uki is fallback (includes PCR11 measurements)
// Using a variant directory allows systemd-pcrlock to try multiple predictions
func LockUKIWithPEFallback(ukiPath string) error {
	stdout, stderr := cmdOutput()
	variantDir := filepath.Join(PCRLockDir, "510-uki.pcrlock.d")

	// Remove old single-file pcrlock if exists (we're switching to variant directory)
	os.Remove(filepath.Join(PCRLockDir, "510-uki.pcrlock"))

	// Create variant directory
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	// Clean variant directory before creating new locks to remove stale files
	if entries, err := os.ReadDir(variantDir); err == nil {
		for _, entry := range entries {
			os.Remove(filepath.Join(variantDir, entry.Name()))
		}
	}

	// Variant 1: lock-pe for the specified UKI (more reliable for PCR4)
	pePath := filepath.Join(variantDir, "pe.pcrlock")
	cmd := exec.Command(PCRLockBin, "lock-pe", ukiPath, "--pcrlock="+pePath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-pe failed: %w", err)
	}

	// Variant 2: lock-uki (includes PCR11 measurements)
	ukiLockPath := filepath.Join(variantDir, "uki.pcrlock")
	cmd = exec.Command(PCRLockBin, "lock-uki", ukiPath, "--pcrlock="+ukiLockPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Ignore lock-uki errors - it's a fallback and may fail on some systems
	cmd.Run()

	// Variant 3: Capture current boot's PCR 4 from event log
	// This ensures the currently booted kernel is recognized even if the file was replaced
	if err := lockCurrentBootPCR4(variantDir); err != nil {
		// Non-fatal - just means current boot won't match but new kernel will
		if Verbose {
			fmt.Printf("Note: Could not capture current boot PCR 4: %v\n", err)
		}
	}

	return nil
}

// lockCurrentBootPCR4 extracts the kernel's PCR 4 measurement from the event log
// and creates a variant pcrlock file for it. This allows the policy to work with
// the currently booted kernel even if the kernel file has been replaced on disk.
//
// We only extract the EV_EFI_BOOT_SERVICES_APPLICATION event for the kernel,
// not firmware events (EV_EFI_ACTION, EV_SEPARATOR) which are handled by
// systemd-pcrlock's firmware component matching.
func lockCurrentBootPCR4(variantDir string) error {
	// Read the event log in CEL-JSON format
	cmd := exec.Command(PCRLockBin, "cel")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read event log: %w", err)
	}

	// Parse the CEL-JSON to find PCR 4 records
	var events []map[string]interface{}
	if err := json.Unmarshal(output, &events); err != nil {
		return fmt.Errorf("failed to parse event log: %w", err)
	}

	// Find the kernel boot application measurement in PCR 4
	// We look for EV_EFI_BOOT_SERVICES_APPLICATION events which measure loaded PE images
	var kernelRecords []map[string]interface{}
	for _, event := range events {
		pcr, ok := event["pcr"].(float64)
		if !ok || int(pcr) != 4 {
			continue
		}

		// Check if this is an EFI boot services application event (kernel/UKI load)
		content, ok := event["content"].(map[string]interface{})
		if !ok {
			continue
		}
		eventType, ok := content["event_type"].(string)
		if !ok {
			continue
		}

		// Only include EV_EFI_BOOT_SERVICES_APPLICATION - this is the kernel measurement
		// Skip firmware events like EV_EFI_ACTION and EV_SEPARATOR
		if eventType == "EV_EFI_BOOT_SERVICES_APPLICATION" {
			// Create a simplified record with just pcr and digests (like lock-pe output)
			digests, ok := event["digests"].([]interface{})
			if !ok {
				continue
			}
			record := map[string]interface{}{
				"pcr":     4,
				"digests": digests,
			}
			kernelRecords = append(kernelRecords, record)
		}
	}

	if len(kernelRecords) == 0 {
		return fmt.Errorf("no kernel boot application records found in event log")
	}

	// Create a pcrlock file matching the format used by lock-pe
	pcrlock := map[string]interface{}{
		"records": kernelRecords,
	}

	data, err := json.MarshalIndent(pcrlock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal pcrlock: %w", err)
	}

	eventLogPath := filepath.Join(variantDir, "eventlog.pcrlock")
	if err := os.WriteFile(eventLogPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write eventlog pcrlock: %w", err)
	}

	return nil
}

// CleanupOldNVIndices removes old pcrlock NV indices from the TPM NVRAM,
// keeping only the indices currently in use by the policy and LUKS token.
// This prevents NVRAM exhaustion from repeated policy updates.
func CleanupOldNVIndices(keepIndices []int) (int, error) {
	// Get all NV indices from TPM
	allIndices, err := listNVIndices()
	if err != nil {
		return 0, fmt.Errorf("failed to list NV indices: %w", err)
	}

	// Build set of indices to keep
	keepSet := make(map[int]bool)
	for _, idx := range keepIndices {
		keepSet[idx] = true
	}

	removed := 0
	for _, idx := range allIndices {
		// Skip indices we want to keep
		if keepSet[idx] {
			continue
		}

		// Only remove indices that look like pcrlock indices
		if !isPCRLockNVIndex(idx) {
			continue
		}

		// Try to remove the index
		if Verbose {
			fmt.Printf("      Removing old NV index: 0x%x\n", idx)
		}
		if err := removeNVIndex(idx); err != nil {
			if Verbose {
				fmt.Printf("      Warning: failed to remove 0x%x: %v\n", idx, err)
			}
			// Continue with other indices
			continue
		}
		removed++
	}

	return removed, nil
}

// listNVIndices returns all NV indices defined in the TPM
func listNVIndices() ([]int, error) {
	cmd := exec.Command("tpm2_getcap", "handles-nv-index")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var indices []int
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Lines look like "- 0x180D9B3"
		if strings.HasPrefix(line, "- 0x") || strings.HasPrefix(line, "-0x") {
			hexStr := strings.TrimPrefix(strings.TrimPrefix(line, "- "), "-")
			if idx, err := strconv.ParseInt(strings.TrimPrefix(hexStr, "0x"), 16, 64); err == nil {
				indices = append(indices, int(idx))
			}
		}
	}

	return indices, scanner.Err()
}

// isPCRLockNVIndex checks if an NV index looks like a pcrlock index
// by checking its attributes and size
func isPCRLockNVIndex(idx int) bool {
	// pcrlock indices are in the owner hierarchy range (0x01800000 - 0x01BFFFFF)
	if idx < nvIndexMin || idx > nvIndexMax {
		return false
	}

	// Check the index attributes using tpm2_nvreadpublic
	cmd := exec.Command("tpm2_nvreadpublic", fmt.Sprintf("0x%x", idx))
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	outputStr := string(output)

	// pcrlock indices have these characteristics:
	// - size: 34 (SHA256 hash + 2 byte header)
	// - attributes include: policywrite, ownerread
	// - do NOT have: platformcreate (those are firmware indices)
	if strings.Contains(outputStr, "platformcreate") {
		return false
	}
	if !strings.Contains(outputStr, "policywrite") {
		return false
	}
	if !strings.Contains(outputStr, "ownerread") {
		return false
	}
	if !strings.Contains(outputStr, "size: 34") {
		return false
	}

	return true
}

// removeNVIndex removes an NV index from the TPM
func removeNVIndex(idx int) error {
	cmd := exec.Command("tpm2_nvundefine", fmt.Sprintf("0x%x", idx))
	return cmd.Run()
}
