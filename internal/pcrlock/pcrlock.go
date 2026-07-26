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
	// PCRLockDir is the directory for pcrlock policy files
	PCRLockDir = "/etc/pcrlock.d"

	// NV index range used by systemd-pcrlock (owner hierarchy, ordinary index)
	// These are in the range 0x01800000 - 0x01BFFFFF (TPM_HT_NV_INDEX | TPM_RH_OWNER)
	nvIndexMin = 0x01800000
	nvIndexMax = 0x01BFFFFF
)

// PCRLockBinPath returns the path to the systemd-pcrlock binary,
// auto-detecting between Gentoo (/lib) and standard (/usr/lib) paths.
func PCRLockBinPath() string {
	for _, p := range []string{
		"/lib/systemd/systemd-pcrlock",
		"/usr/lib/systemd/systemd-pcrlock",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/lib/systemd/systemd-pcrlock"
}

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
//
// 750-os-separator and 770-nvpcr-separator are masked because they expect
// systemd's userspace PCR measurements (EV_SEPARATOR events extended by
// systemd-pcrlock-machine-id / systemd-pcrlock-os-separator). Vanguard's
// custom init does not extend these PCRs, so the components can never match
// the event log. When a component can't match, systemd-pcrlock drops every PCR
// it touches (0-7, 9, 12-14) with "touched by component we can't find",
// cascading to drop ALL PCRs including PCR 7.
var maskedPolicies = []string{
	"200-firmware-code.pcrlock",
	"220-firmware-config.pcrlock",
	"250-firmware-code-early.pcrlock",
	"250-firmware-config-early.pcrlock",
	"750-enter-initrd.pcrlock",
	"750-os-separator.pcrlock",
	"770-nvpcr-separator.pcrlock",
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

// RegenerateFirmwareComponents refreshes the stale auto-generated firmware
// component files in /var/lib/pcrlock.d/ by running systemd-pcrlock's
// lock-firmware-code and lock-firmware-config commands. These generate
// .pcrlock files from the current boot's firmware event log, ensuring the
// component digests match what the firmware actually measured this boot.
//
// Without this, a stale generated.pcrlock (e.g. from a previous firmware
// version or a different boot) causes systemd-pcrlock to report "event log
// contains unrecognized measurements" and drop the PCR from the protection
// mask. Since PCR 0/1 are at the root of the component dependency chain,
// dropping them cascades to drop EVERY PCR — including PCR 7 (secure-boot).
//
// This must be called BEFORE MakePolicy so make-policy sees fresh components.
//
// On systemd v262+ with the io.systemd.PCRLock Varlink interface available,
// this uses the Varlink Lock method (category=firmwareCode/firmwareConfig,
// lock=true) instead of shelling out to the CLI. On older systemd, it falls
// back to exec.Command("systemd-pcrlock", "lock-firmware-code", ...).
func RegenerateFirmwareComponents() error {
	// Try Varlink first (systemd v262+)
	vc := NewVarlinkClient()
	if vc.IsAvailable() {
		if Verbose {
			fmt.Println("[+] Using Varlink interface for firmware component regeneration")
		}
		if err := vc.LockCategory(CategoryFirmwareCode, true); err != nil {
			if Verbose {
				fmt.Printf("Note: Varlink lock firmwareCode failed: %v\n", err)
			}
			// Fall back to CLI
			return regenerateFirmwareComponentsCLI()
		}
		if err := vc.LockCategory(CategoryFirmwareConfig, true); err != nil {
			if Verbose {
				fmt.Printf("Note: Varlink lock firmwareConfig failed: %v\n", err)
			}
			return regenerateFirmwareComponentsCLI()
		}
		return nil
	}

	// CLI fallback (systemd <262 or Varlink unavailable)
	return regenerateFirmwareComponentsCLI()
}

// regenerateFirmwareComponentsCLI is the exec.Command fallback path.
func regenerateFirmwareComponentsCLI() error {
	// lock-firmware-code regenerates PCR 0 firmware code components
	if err := runPCRLock("lock-firmware-code"); err != nil {
		if Verbose {
			fmt.Printf("Note: lock-firmware-code failed (may be harmless): %v\n", err)
		}
		// Non-fatal: if lock-firmware-code fails, the stale component remains.
		// make-policy will still try to match it and may drop PCR 0, but that
		// is the existing behavior — we haven't made things worse.
	}

	// lock-firmware-config regenerates PCR 1 firmware config components
	if err := runPCRLock("lock-firmware-config"); err != nil {
		if Verbose {
			fmt.Printf("Note: lock-firmware-config failed (may be harmless): %v\n", err)
		}
	}

	return nil
}

// runPCRLock runs a systemd-pcrlock subcommand, forwarding output to the
// configured stdout/stderr writers.
func runPCRLock(args ...string) error {
	stdout, stderr := cmdOutput()
	cmd := exec.Command(PCRLockBinPath(), args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// LockSecureBoot locks PCR 7 (policy + authority).
//
// On systemd v262+ with the io.systemd.PCRLock Varlink interface available,
// this uses the Varlink Lock method (category=secureBootPolicy/secureBootAuthority,
// lock=true) instead of shelling out to the CLI. On older systemd, it falls
// back to exec.Command("systemd-pcrlock", "lock-secureboot-policy", ...).
func LockSecureBoot() error {
	// Try Varlink first (systemd v262+)
	vc := NewVarlinkClient()
	if vc.IsAvailable() {
		if Verbose {
			fmt.Println("[+] Using Varlink interface for SecureBoot lock")
		}
		if err := vc.LockCategory(CategorySecureBootPolicy, true); err != nil {
			if Verbose {
				fmt.Printf("Note: Varlink lock secureBootPolicy failed: %v, falling back to CLI\n", err)
			}
			return lockSecureBootCLI()
		}
		if err := vc.LockCategory(CategorySecureBootAuth, true); err != nil {
			if Verbose {
				fmt.Printf("Note: Varlink lock secureBootAuthority failed: %v, falling back to CLI\n", err)
			}
			return lockSecureBootCLI()
		}
		return nil
	}

	// CLI fallback (systemd <262 or Varlink unavailable)
	return lockSecureBootCLI()
}

// lockSecureBootCLI is the exec.Command fallback path.
func lockSecureBootCLI() error {
	stdout, stderr := cmdOutput()

	// Lock secureboot policy
	cmd := exec.Command(PCRLockBinPath(), "lock-secureboot-policy")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-secureboot-policy failed: %w", err)
	}

	// Lock secureboot authority
	cmd = exec.Command(PCRLockBinPath(), "lock-secureboot-authority")
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
	cmd := exec.Command(PCRLockBinPath(), args...)

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

// MakePolicy generates policy with recovery PIN prompt.
//
// In non-verbose mode, stderr is captured (not discarded) so that on failure
// the diagnostic output from systemd-pcrlock (e.g. "PCR 7 dropped from
// protection mask") is included in the error message. Without this, the user
// sees only "make-policy failed: exit status 1" with no clue why PCRs were
// dropped.
func MakePolicy(outputPath string) error {
	stdout, _ := cmdOutput()

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

	cmd := exec.Command(PCRLockBinPath(), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout

	// Always capture stderr. In verbose mode, pipe to os.Stderr for live display.
	// In non-verbose mode, capture to a buffer so we can include it in error
	// messages on failure. This is critical for debugging "PCR missing from
	// policy" errors — without stderr the user only sees "exit status 1".
	var stderrBuf bytes.Buffer
	if Verbose {
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stderr = &stderrBuf
	}

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderrBuf.String())
		if stderrStr != "" {
			return fmt.Errorf("make-policy failed: %w\nstderr:\n%s", err, stderrStr)
		}
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
	cmd := exec.Command(PCRLockBinPath(), "lock-pe", ukiPath, "--pcrlock="+pePath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock-pe failed: %w", err)
	}

	// Variant 2: lock-uki (includes PCR11 measurements)
	ukiLockPath := filepath.Join(variantDir, "uki.pcrlock")
	cmd = exec.Command(PCRLockBinPath(), "lock-uki", ukiPath, "--pcrlock="+ukiLockPath)
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
// On a UKI system, multiple EV_EFI_BOOT_SERVICES_APPLICATION events may appear
// on PCR 4 (shim, bootloader, sd-stub, kernel). We take only the LAST one,
// which is the kernel/UKI — firmware loads EFI applications in order, and the
// kernel is the final EV_EFI_BOOT_SERVICES_APPLICATION before ExitBootServices.
//
// We skip firmware events (EV_EFI_ACTION, EV_SEPARATOR) which are handled by
// systemd-pcrlock's firmware component matching.
func lockCurrentBootPCR4(variantDir string) error {
	// Read the event log in CEL-JSON format
	cmd := exec.Command(PCRLockBinPath(), "cel")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read event log: %w", err)
	}

	// Parse the CEL-JSON to find PCR 4 records
	var events []map[string]interface{}
	if err := json.Unmarshal(output, &events); err != nil {
		return fmt.Errorf("failed to parse event log: %w", err)
	}

	// Find the last EV_EFI_BOOT_SERVICES_APPLICATION event on PCR 4.
	// This is the kernel measurement — firmware loads EFI apps in order
	// (shim → bootloader → sd-stub → kernel), so the last one is the UKI.
	var kernelRecord map[string]interface{}
	for _, event := range events {
		pcr, ok := event["pcr"].(float64)
		if !ok || int(pcr) != 4 {
			continue
		}

		content, ok := event["content"].(map[string]interface{})
		if !ok {
			continue
		}
		eventType, ok := content["event_type"].(string)
		if !ok {
			continue
		}

		if eventType == "EV_EFI_BOOT_SERVICES_APPLICATION" {
			digests, ok := event["digests"].([]interface{})
			if !ok {
				continue
			}
			// Keep the last matching record — this is the kernel
			kernelRecord = map[string]interface{}{
				"pcr":     4,
				"digests": digests,
			}
		}
	}

	if kernelRecord == nil {
		return fmt.Errorf("no kernel boot application records found in event log")
	}

	// Create a pcrlock file matching the format used by lock-pe
	pcrlockFile := map[string]interface{}{
		"records": []map[string]interface{}{kernelRecord},
	}

	data, err := json.MarshalIndent(pcrlockFile, "", "  ")
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
		return nil, fmt.Errorf("tpm2_getcap handles-nv-index failed: %w", err)
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
