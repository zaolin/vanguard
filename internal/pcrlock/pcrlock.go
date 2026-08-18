package pcrlock

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// PCRLockDir is the directory for pcrlock policy files.
// This is a var (not const) so tests can override it.
var PCRLockDir = "/etc/pcrlock.d"

const (
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
//
// Note: 850-sysinit and 900-ready are NOT masked. They are statically-defined
// components that match systemd's sysinit/ready phase measurements on PCR 11.
// make-policy validates the entire event log (not just up to --location), so
// if these are masked, PCR 11 gets "unrecognized measurements" and is dropped.
// With --location=756, the prediction is computed before these phases, but
// validation still needs to match them. Keeping them unmasked allows full
// PCR 11 validation while the --location parameter controls the prediction point.
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

// previouslyMaskedPolicies lists entries that were previously in maskedPolicies
// but have been removed. ConfigureMasks() unmasks these to remove stale
// /dev/null symlinks from previous vanguard update runs.
var previouslyMaskedPolicies = []string{
	"850-sysinit.pcrlock",
	"900-ready.pcrlock",
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

	// Remove stale masks — entries that were previously in maskedPolicies
	// but have been removed. Without this, old symlinks to /dev/null persist
	// and cause make-policy to see those components as masked even though
	// the code no longer masks them.
	for _, name := range previouslyMaskedPolicies {
		if err := UnmaskPolicy(name); err != nil {
			// Non-fatal — just log
			if Verbose {
				fmt.Printf("Note: failed to unmask stale %s: %v\n", name, err)
			}
		}
	}

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

// LockLUKSHeader creates pcrlock component files that predict the PCR 11
// extension from the LUKS2 header measurement. During boot, vanguard's init
// hashes the LUKS2 header and extends PCR 11 with the hash.
//
// Two variants are created:
//
//  1. luks-header.pcrlock — uses the current on-disk LUKS header hash.
//     This matches the NEXT boot (after the policy is applied).
//
//  2. luks-header-eventlog.pcrlock — uses the LUKS header hash from the
//     current boot's event log. This matches the CURRENT boot so make-policy
//     can validate the event log. Without this, make-policy sees the component
//     as "not found in event log" because the on-disk hash differs from the
//     event log hash (the header changes when vanguard update re-enrolls the
//     TPM2 token).
//
// The component directory is placed at:
//
//	/etc/pcrlock.d/755-vanguard-luks-header.pcrlock.d/
//
// The 755- prefix places it between 750-enter-initrd (masked) and
// 800-leave-initrd (masked), reflecting that the measurement happens
// during initrd phase.
func LockLUKSHeader(devicePath string) error {
	digest, err := computeLUKSHeaderDigest(devicePath)
	if err != nil {
		return fmt.Errorf("failed to hash LUKS2 header: %w", err)
	}

	// Create variant directory
	variantDir := filepath.Join(PCRLockDir, "755-vanguard-luks-header.pcrlock.d")
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		return fmt.Errorf("failed to create LUKS header variant directory: %w", err)
	}

	// Clean variant directory before creating new locks
	if entries, err := os.ReadDir(variantDir); err == nil {
		for _, entry := range entries {
			os.Remove(filepath.Join(variantDir, entry.Name()))
		}
	}

	// Variant 1: On-disk LUKS header hash (matches next boot)
	pcrlockFile := map[string]interface{}{
		"records": []map[string]interface{}{
			{
				"pcr": 11,
				"digests": []map[string]interface{}{
					{
						"hashAlg": "sha256",
						"digest":  fmt.Sprintf("%x", digest),
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(pcrlockFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal LUKS header pcrlock: %w", err)
	}

	pcrlockPath := filepath.Join(variantDir, "luks-header.pcrlock")
	if err := os.WriteFile(pcrlockPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write LUKS header pcrlock: %w", err)
	}

	if Verbose {
		fmt.Printf("[+] Locked LUKS header for %s (PCR 11, digest: %x)\n", devicePath, digest)
	}

	// Variant 2: Event log LUKS header hash (matches current boot)
	// This is critical: vanguard update re-enrolls the TPM2 token, which
	// changes the LUKS2 JSON metadata, which changes the header hash. The
	// event log has the OLD hash (from the last boot), but the on-disk
	// variant has the NEW hash. Without an eventlog variant, make-policy
	// can't match the component against the event log and drops PCR 11.
	if err := lockLUKSHeaderEventlog(variantDir); err != nil {
		// Non-fatal — just means current boot won't match but next boot will
		if Verbose {
			fmt.Printf("Note: Could not capture LUKS header from event log: %v\n", err)
		}
	}

	return nil
}

// MaskLUKSHeader removes the LUKS header pcrlock component by symlinking to
// /dev/null, so make-policy ignores it. Used when --no-luks-header is passed
// or when the device is not LUKS-encrypted.
func MaskLUKSHeader() error {
	return MaskPolicy("755-vanguard-luks-header.pcrlock")
}

// lockLUKSHeaderEventlog extracts the vanguard-luks-header PCR 11 record from
// the current boot's event log and creates a variant pcrlock file for it.
// This ensures make-policy can match the component against the event log even
// when the on-disk LUKS header hash differs (e.g., after vanguard update
// re-enrolls the TPM2 token, changing the LUKS2 JSON metadata).
//
// The record is identified by exclusion: sd-stub measurements have
// content_type "pcclient_std" and systemd phase measurements have
// content_type "systemd". Our vanguard-luks-header record has neither
// (systemd-pcrlock cel strips unrecognized content), so we pick the
// PCR 11 record that doesn't match either known content_type.
func lockLUKSHeaderEventlog(variantDir string) error {
	digest, err := findLUKSHeaderDigestFromEventLog()
	if err != nil {
		return err
	}

	pcrlockFile := map[string]interface{}{
		"records": []map[string]interface{}{
			{
				"pcr": 11,
				"digests": []map[string]interface{}{
					{
						"hashAlg": "sha256",
						"digest":  fmt.Sprintf("%x", digest),
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(pcrlockFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal eventlog LUKS header pcrlock: %w", err)
	}

	eventlogPath := filepath.Join(variantDir, "luks-header-eventlog.pcrlock")
	if err := os.WriteFile(eventlogPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write eventlog LUKS header pcrlock: %w", err)
	}

	if Verbose {
		fmt.Printf("[+] Captured LUKS header from event log (luks-header-eventlog.pcrlock)\n")
	}

	return nil
}

// findLUKSHeaderDigestFromEventLog reads the combined event log via
// `systemd-pcrlock cel` and finds the vanguard-luks-header PCR 11 record.
// The record is identified by exclusion: it's the PCR 11 record that
// doesn't have content_type "pcclient_std" (sd-stub) or "systemd" (phases).
func findLUKSHeaderDigestFromEventLog() ([]byte, error) {
	cmd := exec.Command(PCRLockBinPath(), "cel")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read event log: %w", err)
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(output, &events); err != nil {
		return nil, fmt.Errorf("failed to parse event log: %w", err)
	}

	for _, event := range events {
		pcr, ok := event["pcr"].(float64)
		if !ok || int(pcr) != 11 {
			continue
		}

		// Skip sd-stub measurements (content_type: "pcclient_std")
		contentType, _ := event["content_type"].(string)
		if contentType == "pcclient_std" {
			continue
		}
		// Skip systemd phase measurements (content_type: "systemd")
		if contentType == "systemd" {
			continue
		}

		// This is our vanguard-luks-header record (no recognized content_type)
		digests, ok := event["digests"].([]interface{})
		if !ok {
			continue
		}

		for _, d := range digests {
			dMap, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			hashAlg, _ := dMap["hashAlg"].(string)
			digestHex, _ := dMap["digest"].(string)
			if hashAlg == "sha256" && digestHex != "" {
				return hex.DecodeString(digestHex)
			}
		}
	}

	return nil, fmt.Errorf("no vanguard-luks-header record found in event log")
}

// InjectLUKSHeaderPrediction post-processes a pcrlock.json policy file to
// add the predicted PCR 11 value using the current on-disk LUKS header hash.
//
// This is needed because make-policy generates the policy using the event log
// (which has the OLD LUKS header hash from the last boot), but the NEXT boot
// will use the NEW hash (after vanguard update re-enrolled the TPM2 token).
//
// The function:
//  1. Reads the existing pcrlock.json
//  2. Replays all PCR 11 records from the event log (sd-stub + old LUKS hash)
//     to compute the PCR 11 value that make-policy predicted
//  3. Replaces the old LUKS hash with the new on-disk hash and recomputes
//     the predicted PCR 11 value
//  4. Adds the new predicted value as an additional value for PCR 11 in the
//     policy's pcrValues array (PolicyOR — accepts either old or new)
//
// On the next boot, init measures the NEW hash → PCR 11 matches the injected
// prediction → unseal succeeds. After that boot, make-policy regenerates the
// policy cleanly (event log now has the new hash).
func InjectLUKSHeaderPrediction(policyPath, devicePath string) error {
	// Read the on-disk LUKS header hash
	newDigest, err := computeLUKSHeaderDigest(devicePath)
	if err != nil {
		return fmt.Errorf("failed to hash LUKS header: %w", err)
	}

	// Read the event log to get the old LUKS header hash and all PCR 11
	// records that come before it (sd-stub measurements)
	cmd := exec.Command(PCRLockBinPath(), "cel")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read event log: %w", err)
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(output, &events); err != nil {
		return fmt.Errorf("failed to parse event log: %w", err)
	}

	// Collect all PCR 11 extension digests in order (sd-stub + LUKS header).
	// We need to replay them to compute the predicted PCR 11 value.
	// The LUKS header record is identified by exclusion: it's the PCR 11
	// record that doesn't have content_type "pcclient_std" (sd-stub) or
	// "systemd" (phases). systemd-pcrlock cel strips the content field
	// from unrecognized records, so we can't search by content string.
	var pcr11Extensions [][]byte
	var oldLUKSDigest []byte
	foundLUKS := false

	for _, event := range events {
		pcr, ok := event["pcr"].(float64)
		if !ok || int(pcr) != 11 {
			continue
		}

		digests, ok := event["digests"].([]interface{})
		if !ok {
			continue
		}

		// Extract sha256 digest
		for _, d := range digests {
			dMap, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			hashAlg, _ := dMap["hashAlg"].(string)
			digestHex, _ := dMap["digest"].(string)
			if hashAlg != "sha256" {
				continue
			}

			digest, err := hex.DecodeString(digestHex)
			if err != nil {
				continue
			}

			// Identify the vanguard-luks-header record by exclusion.
			// sd-stub records have content_type "pcclient_std".
			// systemd phase records have content_type "systemd".
			// Our record has neither (stripped by cel).
			contentType, _ := event["content_type"].(string)
			if contentType != "pcclient_std" && contentType != "systemd" {
				oldLUKSDigest = digest
				foundLUKS = true
				// Don't add to pcr11Extensions — we'll replace with new digest
			} else {
				pcr11Extensions = append(pcr11Extensions, digest)
			}
		}
	}

	if !foundLUKS {
		// No LUKS header record in event log — nothing to inject
		if Verbose {
			fmt.Printf("Note: No vanguard-luks-header record in event log, skipping injection\n")
		}
		return nil
	}

	// Compute predicted PCR 11 with OLD hash (what make-policy predicted)
	// Replay: PCR11 = SHA256(SHA256(...SHA256(0 || ext1) || ext2...) || oldLUKS)
	pcr11Old := make([]byte, 32) // start with all-zeros
	for _, ext := range pcr11Extensions {
		h := sha256.New()
		h.Write(pcr11Old)
		h.Write(ext)
		pcr11Old = h.Sum(nil)
	}
	if oldLUKSDigest != nil {
		h := sha256.New()
		h.Write(pcr11Old)
		h.Write(oldLUKSDigest)
		pcr11Old = h.Sum(nil)
	}

	// Compute predicted PCR 11 with NEW hash (what the next boot will produce)
	pcr11New := make([]byte, 32)
	for _, ext := range pcr11Extensions {
		h := sha256.New()
		h.Write(pcr11New)
		h.Write(ext)
		pcr11New = h.Sum(nil)
	}
	h := sha256.New()
	h.Write(pcr11New)
	h.Write(newDigest)
	pcr11New = h.Sum(nil)

	// Read the existing policy
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// Find or create PCR 11 entry in pcrValues
	pcrValues, ok := policy["pcrValues"].([]interface{})
	if !ok {
		pcrValues = []interface{}{}
	}

	newPCR11Value := hex.EncodeToString(pcr11New)
	oldPCR11Value := hex.EncodeToString(pcr11Old)

	// Check if PCR 11 is already in the policy
	foundPCR11 := false
	for i, pv := range pcrValues {
		pvMap, ok := pv.(map[string]interface{})
		if !ok {
			continue
		}
		pcr, ok := pvMap["pcr"].(float64)
		if ok && int(pcr) == 11 {
			foundPCR11 = true
			// Add the new predicted value if not already present
			values, ok := pvMap["values"].([]interface{})
			if !ok {
				values = []interface{}{}
			}

			// Check if new value is already present
			alreadyPresent := false
			for _, v := range values {
				if vStr, ok := v.(string); ok && vStr == newPCR11Value {
					alreadyPresent = true
					break
				}
			}

			if !alreadyPresent {
				values = append(values, newPCR11Value)
				pvMap["values"] = values
				pcrValues[i] = pvMap
				if Verbose {
					fmt.Printf("[+] Injected PCR 11 prediction for new LUKS header hash: %s\n",
						newPCR11Value[:20])
				}
			}

			break
		}
	}

	// If PCR 11 is not in the policy at all, add it with both old and new values
	if !foundPCR11 {
		pcr11Entry := map[string]interface{}{
			"pcr":    11,
			"values": []interface{}{oldPCR11Value, newPCR11Value},
		}
		pcrValues = append(pcrValues, pcr11Entry)
		if Verbose {
			fmt.Printf("[+] Added PCR 11 to policy with old (%s...) and new (%s...) predictions\n",
				oldPCR11Value[:20], newPCR11Value[:20])
		}
	}

	policy["pcrValues"] = pcrValues

	// Write the modified policy
	updatedData, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated policy: %w", err)
	}

	if err := os.WriteFile(policyPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated policy: %w", err)
	}

	return nil
}

// computeLUKSHeaderDigest reads the LUKS2 header from the device and returns
// its SHA256 hash. The header size is determined from the hdr_len field at
// offset 8 in the binary header.
func computeLUKSHeaderDigest(devicePath string) ([]byte, error) {
	f, err := os.Open(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}
	defer f.Close()

	// Read binary header (first 32 bytes for magic + version + hdr_len)
	binHeader := make([]byte, 32)
	if _, err := f.ReadAt(binHeader, 0); err != nil {
		return nil, fmt.Errorf("failed to read binary header: %w", err)
	}

	// Check LUKS magic
	if string(binHeader[0:4]) != "LUKS" {
		return nil, fmt.Errorf("not a LUKS device: %s", devicePath)
	}

	// Check version (offset 6, big-endian uint16)
	version := uint16(binHeader[6])<<8 | uint16(binHeader[7])
	if version != 2 {
		return nil, fmt.Errorf("only LUKS2 is supported (found version %d)", version)
	}

	// hdr_len at offset 8 (big-endian uint64)
	hdrLen := uint64(binHeader[8])<<56 |
		uint64(binHeader[9])<<48 |
		uint64(binHeader[10])<<40 |
		uint64(binHeader[11])<<32 |
		uint64(binHeader[12])<<24 |
		uint64(binHeader[13])<<16 |
		uint64(binHeader[14])<<8 |
		uint64(binHeader[15])

	if hdrLen < 0x1000 || hdrLen > 16*1024*1024 {
		return nil, fmt.Errorf("invalid LUKS2 header length: %d", hdrLen)
	}

	// Read the full header (binary header + JSON area)
	fullHeader := make([]byte, hdrLen)
	if _, err := f.ReadAt(fullHeader, 0); err != nil {
		return nil, fmt.Errorf("failed to read full LUKS2 header: %w", err)
	}

	hash := sha256.Sum256(fullHeader)
	return hash[:], nil
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

	// Use --location=756 to limit the prediction window to our
	// 755-vanguard-luks-header.pcrlock component. This is critical:
	//
	// systemd-pcrlock make-policy validates the entire event log against
	// component files. PCR 11 has measurements from systemd's sysinit/ready
	// phases (recnum 100-101) that happen AFTER LUKS unlock. Those
	// components (850-sysinit, 900-ready) are masked, so make-policy sees
	// "unrecognized measurements" on PCR 11 and refuses to predict it.
	//
	// By setting --location=756, we tell make-policy to only predict up to
	// component 755 (our LUKS header component). Measurements after that
	// point (sysinit, ready, shutdown) are ignored — they're outside the
	// prediction window. The predicted PCR 11 value includes only the
	// sd-stub kernel measurement + our LUKS header hash, which is exactly
	// the PCR 11 state at LUKS unseal time.
	//
	// systemd's own make-policy.service uses --location=770 for the same
	// reason: it predicts up to the nvpcr-separator, excluding leave-initrd
	// and later phases that haven't happened at disk-unlock time.
	args := []string{"make-policy", "--policy=" + outputPath, "--force",
		"--recovery-pin=query", "--location=756"}
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

	// Variant 4: Capture current boot's PCR 11 from event log
	// This is critical for LUKS header binding (PCR 11). The uki.pcrlock variant
	// measures the on-disk UKI file, which becomes stale when the initrd is
	// regenerated (the .initrd section measurement changes). This variant uses
	// the actual boot-time PCR 11 measurements from the event log, so it always
	// matches the current boot. Without this, any initrd change causes PCR 11
	// to be dropped from the policy due to "unrecognized measurements."
	if err := lockCurrentBootPCR11(variantDir); err != nil {
		// Non-fatal - PCR 11 just won't be predicted from event log
		if Verbose {
			fmt.Printf("Note: Could not capture current boot PCR 11: %v\n", err)
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

// lockCurrentBootPCR11 extracts all PCR 11 sd-stub measurements from the event
// log and creates a variant pcrlock file for them. This ensures PCR 11 is
// always predictable even when the on-disk UKI file (and thus uki.pcrlock)
// becomes stale after initrd regeneration.
//
// sd-stub measures UKI sections (.linux, .osrel, .sbat, .cmdline, .initrd,
// .sb, etc.) into PCR 11 as EV_IPL events. These appear in the firmware event
// log (not the userspace event log) because sd-stub runs before the kernel.
// We capture all PCR 11 EV_IPL records from the firmware event log and write
// them as a pcrlock variant.
//
// This variant also includes the PCR 4 record from the event log, so it
// covers both PCR 4 and PCR 11 in a single variant (like uki.pcrlock does).
func lockCurrentBootPCR11(variantDir string) error {
	// Read the event log in CEL-JSON format
	cmd := exec.Command(PCRLockBinPath(), "cel")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read event log: %w", err)
	}

	// Parse the CEL-JSON
	var events []map[string]interface{}
	if err := json.Unmarshal(output, &events); err != nil {
		return fmt.Errorf("failed to parse event log: %w", err)
	}

	// Collect ALL PCR 11 records from the firmware event log.
	// sd-stub measures UKI sections as EV_IPL events into PCR 11.
	// We also collect the last EV_EFI_BOOT_SERVICES_APPLICATION on PCR 4
	// (the kernel measurement) to cover PCR 4 in this variant.
	var pcr11Records []map[string]interface{}
	var pcr4Record map[string]interface{}

	for _, event := range events {
		pcr, ok := event["pcr"].(float64)
		if !ok {
			continue
		}

		content, ok := event["content"].(map[string]interface{})
		if !ok {
			continue
		}
		eventType, _ := content["event_type"].(string)

		digests, ok := event["digests"].([]interface{})
		if !ok {
			continue
		}

		switch int(pcr) {
		case 11:
			// Capture all PCR 11 EV_IPL records (sd-stub section measurements)
			if eventType == "EV_IPL" {
				pcr11Records = append(pcr11Records, map[string]interface{}{
					"pcr":     11,
					"digests": digests,
				})
			}
		case 4:
			// Keep the last EV_EFI_BOOT_SERVICES_APPLICATION (kernel measurement)
			if eventType == "EV_EFI_BOOT_SERVICES_APPLICATION" {
				pcr4Record = map[string]interface{}{
					"pcr":     4,
					"digests": digests,
				}
			}
		}
	}

	if len(pcr11Records) == 0 {
		return fmt.Errorf("no PCR 11 EV_IPL records found in event log")
	}

	// Build the pcrlock file with PCR 4 (if found) + all PCR 11 records
	var records []map[string]interface{}
	if pcr4Record != nil {
		records = append(records, pcr4Record)
	}
	records = append(records, pcr11Records...)

	pcrlockFile := map[string]interface{}{
		"records": records,
	}

	data, err := json.MarshalIndent(pcrlockFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal pcrlock: %w", err)
	}

	eventLogPath := filepath.Join(variantDir, "eventlog-pcr11.pcrlock")
	if err := os.WriteFile(eventLogPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write eventlog-pcr11 pcrlock: %w", err)
	}

	if Verbose {
		fmt.Printf("[+] Captured %d PCR 11 records from event log (eventlog-pcr11.pcrlock)\n",
			len(pcr11Records))
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
