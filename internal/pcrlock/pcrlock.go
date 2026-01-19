package pcrlock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	// PCRLockBin is the path to the systemd-pcrlock binary
	PCRLockBin = "/usr/lib/systemd/systemd-pcrlock"
	// PCRLockDir is the directory for pcrlock policy files
	PCRLockDir = "/etc/pcrlock.d"
)

// Masked policies - noisy/unsupported PCRs that change frequently
// PCR 15 policies are masked because vanguard unlocks LUKS before systemd
// extends PCR 15, causing a timing mismatch with pcrlock predictions
var maskedPolicies = []string{
	"200-firmware-code.pcrlock",
	"220-firmware-config.pcrlock",
	"250-firmware-code-early.pcrlock",
	"250-firmware-config-early.pcrlock",
	"600-gpt.pcrlock",
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
		os.Remove(path) // Ignore errors - file may not exist
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
	// Lock secureboot policy
	cmd := exec.Command(PCRLockBin, "lock-secureboot-policy")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-secureboot-policy failed: %w", err)
	}

	// Lock secureboot authority
	cmd = exec.Command(PCRLockBin, "lock-secureboot-authority")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-secureboot-authority failed: %w", err)
	}

	return nil
}

// LockUKI locks PCR 4 for the given UKI path (single file mode)
func LockUKI(ukiPath string) error {
	cmd := exec.Command(PCRLockBin, "lock-uki", ukiPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-uki failed: %w", err)
	}
	return nil
}

// LockUKIVariant locks PCR 4 for the given UKI path into a variant directory
// This creates /etc/pcrlock.d/100-uki.pcrlock.d/<name>.pcrlock
// Using variants allows both old (currently booted) and new UKI to be valid
func LockUKIVariant(ukiPath string, variantName string) error {
	variantDir := filepath.Join(PCRLockDir, "100-uki.pcrlock.d")
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	pcrLockPath := filepath.Join(variantDir, variantName+".pcrlock")

	cmd := exec.Command(PCRLockBin, "lock-uki", ukiPath, "--pcrlock="+pcrLockPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-uki variant failed: %w", err)
	}
	return nil
}

// LockUKIWithVariants creates UKI variant for the new UKI file
// This allows the policy to work with both currently booted UKI and the new one
func LockUKIWithVariants(newUKIPath string) error {
	variantDir := filepath.Join(PCRLockDir, "100-uki.pcrlock.d")

	// Remove old single-file pcrlock if exists (we're switching to variant directory)
	os.Remove(filepath.Join(PCRLockDir, "100-uki.pcrlock"))

	// Create variant directory
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	// Create new variant from specified UKI file
	newPath := filepath.Join(variantDir, "new.pcrlock")
	cmd := exec.Command(PCRLockBin, "lock-uki", newUKIPath, "--pcrlock="+newPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to lock new UKI: %w", err)
	}

	return nil
}

// LockMachineID locks PCR 15 for machine ID
func LockMachineID() error {
	cmd := exec.Command(PCRLockBin, "lock-machine-id")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-machine-id failed: %w", err)
	}
	return nil
}

// LockFileSystem locks PCR 15 for root filesystem
func LockFileSystem(path string) error {
	cmd := exec.Command(PCRLockBin, "lock-file-system", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-file-system failed: %w", err)
	}
	return nil
}

// MakePolicy generates policy with recovery PIN prompt
func MakePolicy(outputPath string) error {
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
			fmt.Printf("[+] Reusing existing NV Index: 0x%x\n", info.NVIndex)

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
	args = append(args, nvIndexArgs...)

	cmd := exec.Command(PCRLockBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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
	PCRs []int
}

type policyEntry struct {
	PCR int `json:"pcr"`
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
	cmd := exec.Command(PCRLockBin, "lock-pe", pePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-pe failed: %w", err)
	}
	return nil
}

// LockPEVariant locks PCR 4 for PE binary into variant directory
func LockPEVariant(pePath string, variantName string) error {
	variantDir := filepath.Join(PCRLockDir, "100-uki.pcrlock.d")
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create variant directory: %w", err)
	}

	pcrLockPath := filepath.Join(variantDir, variantName+".pcrlock")
	cmd := exec.Command(PCRLockBin, "lock-pe", pePath, "--pcrlock="+pcrLockPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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
	variantDir := filepath.Join(PCRLockDir, "100-uki.pcrlock.d")

	// Remove old single-file pcrlock if exists (we're switching to variant directory)
	os.Remove(filepath.Join(PCRLockDir, "100-uki.pcrlock"))

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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-pe failed: %w", err)
	}

	// Variant 2: lock-uki (includes PCR11 measurements)
	ukiLockPath := filepath.Join(variantDir, "uki.pcrlock")
	cmd = exec.Command(PCRLockBin, "lock-uki", ukiPath, "--pcrlock="+ukiLockPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Ignore lock-uki errors - it's a fallback and may fail on some systems
	cmd.Run()

	// Variant 3: Capture current boot's PCR 4 from event log
	// This ensures the currently booted kernel is recognized even if the file was replaced
	if err := lockCurrentBootPCR4(variantDir); err != nil {
		// Non-fatal - just means current boot won't match but new kernel will
		fmt.Printf("Note: Could not capture current boot PCR 4: %v\n", err)
	}

	return nil
}

// lockCurrentBootPCR4 extracts the current boot's PCR 4 measurement from the event log
// and creates a variant pcrlock file for it
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

	// Find PCR 4 measurements (boot loader code)
	var pcr4Records []map[string]interface{}
	for _, event := range events {
		if pcr, ok := event["pcr"].(float64); ok && int(pcr) == 4 {
			pcr4Records = append(pcr4Records, event)
		}
	}

	if len(pcr4Records) == 0 {
		return fmt.Errorf("no PCR 4 records found in event log")
	}

	// Create a pcrlock file with the current boot's PCR 4 measurements
	pcrlock := map[string]interface{}{
		"records": pcr4Records,
	}

	data, err := json.Marshal(pcrlock)
	if err != nil {
		return fmt.Errorf("failed to marshal pcrlock: %w", err)
	}

	eventLogPath := filepath.Join(variantDir, "eventlog.pcrlock")
	if err := os.WriteFile(eventLogPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write eventlog pcrlock: %w", err)
	}

	return nil
}
