// Package luks provides native LUKS2 device handling for the initramfs.
// This replaces the dependency on the cryptsetup binary.
package luks

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anatol/luks.go"
	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/init/tui"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// Device represents a LUKS encrypted device.
type Device struct {
	Path string
	Name string // Mapped name (e.g., "luks-sda3")
	UUID string
	dev  luks.Device
}

// Debug is set by main.go based on build tags.
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// LogFunc is a callback for boot logging.
var LogFunc func(event string, kvPairs ...string) = func(event string, kvPairs ...string) {}

// StrictMode disables passphrase fallback when TPM2 token is present.
var StrictMode bool = false

// Maximum PIN retry attempts.
const maxPINAttempts = 3

// ErrNoDevices indicates no LUKS devices were found.
var ErrNoDevices = errors.New("no LUKS devices found")

// UnlockDevices discovers and unlocks all LUKS devices.
// Returns true if at least one device was unlocked.
func UnlockDevices() (bool, error) {
	// Wait for block devices to settle
	time.Sleep(500 * time.Millisecond)

	devices, err := DiscoverDevices()
	if err != nil {
		return false, fmt.Errorf("failed to discover LUKS devices: %w", err)
	}

	if len(devices) == 0 {
		return false, nil
	}

	for _, dev := range devices {
		Debug("luks: unlocking %s\n", dev.Path)
		if err := dev.Unlock(); err != nil {
			// Close device on error before returning
			dev.Close()
			return false, fmt.Errorf("failed to unlock %s: %w", dev.Path, err)
		}
		// Close device after successful unlock to free resources
		// The dm-crypt mapping remains active after Close()
		dev.Close()
	}

	return true, nil
}

// DiscoverDevices finds all LUKS devices in the system.
func DiscoverDevices() ([]*Device, error) {
	var devices []*Device
	seen := make(map[string]bool)

	// Scan /sys/block for block devices
	sysBlocks, err := os.ReadDir("/sys/block")
	if err != nil {
		Debug("luks: failed to read /sys/block: %v\n", err)
		return nil, err
	}

	var candidates []string
	for _, block := range sysBlocks {
		name := block.Name()
		// Skip ram, loop, and dm devices
		if strings.HasPrefix(name, "ram") || name == "loop" || strings.HasPrefix(name, "dm-") {
			continue
		}

		devPath := filepath.Join("/dev", name)
		if _, err := os.Stat(devPath); err == nil {
			candidates = append(candidates, devPath)
		}

		// Scan for partitions
		partitions, _ := filepath.Glob(filepath.Join("/sys/block", name, name+"*"))
		for _, part := range partitions {
			partName := filepath.Base(part)
			partDev := filepath.Join("/dev", partName)
			if _, err := os.Stat(partDev); err == nil {
				candidates = append(candidates, partDev)
			}
		}
	}

	Debug("luks: scanning %d block devices\n", len(candidates))

	for _, path := range candidates {
		if seen[path] {
			continue
		}
		seen[path] = true

		if isLUKS(path) {
			Debug("luks: found LUKS device: %s\n", path)
			dev, err := Open(path)
			if err != nil {
				Debug("luks: failed to open %s: %v\n", path, err)
				continue
			}
			devices = append(devices, dev)
		}
	}

	return devices, nil
}

// isLUKS checks if a device has a LUKS header.
func isLUKS(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read LUKS magic header
	magic := make([]byte, 6)
	n, err := f.Read(magic)
	if err != nil || n < 6 {
		return false
	}

	// LUKS magic is "LUKS\xba\xbe"
	return string(magic[:4]) == "LUKS"
}

// Open opens a LUKS device for inspection and unlocking.
func Open(path string) (*Device, error) {
	dev, err := luks.Open(path)
	if err != nil {
		return nil, err
	}

	return &Device{
		Path: path,
		Name: generateMappedName(path),
		UUID: dev.UUID(),
		dev:  dev,
	}, nil
}

// Close closes the LUKS device.
func (d *Device) Close() error {
	if d.dev != nil {
		return d.dev.Close()
	}
	return nil
}

// generateMappedName creates a dm name for the device.
func generateMappedName(path string) string {
	base := filepath.Base(path)
	return "luks-" + base
}

// Unlock attempts to unlock the LUKS device.
func (d *Device) Unlock() error {
	// Check if already unlocked
	mappedPath := "/dev/mapper/" + d.Name
	if _, err := os.Stat(mappedPath); err == nil {
		Debug("luks: %s already unlocked\n", d.Path)
		return nil
	}

	// Check for systemd-tpm2 tokens
	if d.HasTPM2Token() {
		console.DebugPrint("luks: found TPM2 token on %s, trying token unlock\n", d.Path)
		err := d.UnlockWithTPM2()

		if err == nil {
			console.DebugPrint("luks: %s unlocked with TPM2 token\n", d.Path)
			LogFunc("LUKS_UNLOCK", "device", d.Path, "method", "token", "status", "ok")
			return nil
		}

		console.DebugPrint("luks: TPM2 unlock failed: %v\n", err)

		// Strict mode: no passphrase fallback
		if StrictMode {
			console.Print("luks: strict mode - no passphrase fallback\n")
			LogFunc("LUKS_FAIL", "device", d.Path, "method", "token", "error", err.Error(), "mode", "strict")
			return fmt.Errorf("token unlock failed (strict mode): %w", err)
		}

		// Normal mode: fall back to passphrase
		console.Print("luks: falling back to passphrase: %v\n", err)

		// Show failure reason in TUI
		if tui.IsEnabled() {
			msg := formatTPMError(err)
			tui.PasswordError(msg)
		}

		LogFunc("PASSPHRASE_FALLBACK", "device", d.Path, "reason", err.Error())
	}

	// Use passphrase
	if err := d.UnlockWithPassphrase(); err != nil {
		LogFunc("LUKS_FAIL", "device", d.Path, "method", "passphrase", "error", err.Error())
		return err
	}
	LogFunc("LUKS_UNLOCK", "device", d.Path, "method", "passphrase", "status", "ok")
	return nil
}

// HasTPM2Token checks if the device has a systemd-tpm2 token.
func (d *Device) HasTPM2Token() bool {
	tokens, err := d.dev.Tokens()
	if err != nil {
		return false
	}

	for _, token := range tokens {
		if token.Type == "systemd-tpm2" {
			return true
		}
	}
	return false
}

// GetTPM2Token returns the first systemd-tpm2 token, if any.
func (d *Device) GetTPM2Token() (*TPM2Token, error) {
	tokens, err := d.dev.Tokens()
	if err != nil {
		return nil, err
	}

	for _, token := range tokens {
		if token.Type == "systemd-tpm2" {
			return ParseTPM2Token(token)
		}
	}
	return nil, errors.New("no systemd-tpm2 token found")
}

// UnlockWithTPM2 attempts to unlock using the TPM2 token.
func (d *Device) UnlockWithTPM2() error {
	// Wait for TPM device
	tpmClient := intpm.New()
	if !tpmClient.WaitForDevice(3 * time.Second) {
		return fmt.Errorf("%w", intpm.ErrTPMUnavailable)
	}

	// Check lockout status
	status, err := tpmClient.GetLockoutStatus()
	if err == nil && status.InLockout {
		msg := "TPM locked - too many failed attempts"
		hint := ""
		if status.LockoutRecovery > 0 {
			hint = fmt.Sprintf("Wait %d seconds or reboot to clear lockout", status.LockoutRecovery)
		}
		if tui.IsEnabled() {
			tui.ShowTPMLockout(msg, hint)
		} else {
			console.Print("luks: %s\n", msg)
			if hint != "" {
				console.Print("luks: %s\n", hint)
			}
		}
		LogFunc("TPM_LOCKOUT", "device", d.Path, "hint", hint)
		return intpm.ErrTPMLockout
	}

	// Get TPM2 token
	token, err := d.GetTPM2Token()
	if err != nil {
		return err
	}

	if token.NeedsPIN {
		return d.unlockWithTPM2PIN(tpmClient, token)
	}

	return d.unlockWithTPM2NoPIN(tpmClient, token)
}

// unlockWithTPM2NoPIN attempts TPM2 unlock without PIN.
func (d *Device) unlockWithTPM2NoPIN(tpmClient *intpm.Client, token *TPM2Token) error {
	password, err := token.Unseal(tpmClient, nil)
	if err != nil {
		d.logPCRDebug(token)
		return err
	}

	// Unlock with recovered password
	return d.unlockWithKey(password)
}

// unlockWithTPM2PIN attempts TPM2 unlock with PIN and retry logic.
func (d *Device) unlockWithTPM2PIN(tpmClient *intpm.Client, token *TPM2Token) error {
	var lastError error
	var pin string
	var err error

	for attempt := 1; attempt <= maxPINAttempts; attempt++ {
		// Prompt for PIN
		if attempt == 1 {
			if tui.IsEnabled() {
				pin, err = tui.PromptPassword(d.Path + " (TPM PIN)")
			} else {
				pin, err = console.ReadPassword(fmt.Sprintf("Enter TPM2 PIN for %s: ", d.Path))
			}
		}

		if err != nil {
			if tui.IsEnabled() {
				tui.PasswordPromptDone()
			}
			return fmt.Errorf("failed to read PIN: %w", err)
		}

		// Unseal with PIN using native TPM implementation
		password, unsealErr := token.Unseal(tpmClient, []byte(pin))
		if unsealErr == nil {
			// Success - unlock with password
			if tui.IsEnabled() {
				tui.PasswordPromptDone()
			}
			return d.unlockWithKey(password)
		}

		// Classify error
		userMsg := formatTPMError(unsealErr)
		lastError = unsealErr

		// Check if retryable
		if errors.Is(unsealErr, intpm.ErrWrongPIN) && attempt < maxPINAttempts {
			LogFunc("TPM_PIN_FAIL", "device", d.Path, "attempt", fmt.Sprintf("%d", attempt))
			userMsg = fmt.Sprintf("Incorrect PIN (attempt %d of %d)", attempt, maxPINAttempts)
			if tui.IsEnabled() {
				pin, err = tui.PasswordErrorWithRetry(userMsg)
			} else {
				console.Print("luks: %s\n", userMsg)
				pin, err = console.ReadPassword(fmt.Sprintf("Enter TPM2 PIN for %s: ", d.Path))
			}
			continue
		}

		// Non-retryable or last attempt
		if tui.IsEnabled() {
			if errors.Is(unsealErr, intpm.ErrTPMLockout) {
				status, _ := tpmClient.GetLockoutStatus()
				hint := ""
				if status != nil && status.LockoutRecovery > 0 {
					hint = fmt.Sprintf("Wait %d seconds or reboot", status.LockoutRecovery)
				}
				tui.ShowTPMLockout(userMsg, hint)
			} else if errors.Is(unsealErr, intpm.ErrPCRMismatch) {
				tui.ShowTPMError(userMsg)
				tui.PasswordPromptDone()
			} else {
				tui.PasswordError(userMsg)
				tui.PasswordPromptDone()
			}
		} else {
			console.Print("luks: %s\n", userMsg)
		}

		if !errors.Is(unsealErr, intpm.ErrWrongPIN) {
			d.logPCRDebug(token)
			LogFunc("TPM_ERROR", "device", d.Path, "message", userMsg)
		} else {
			LogFunc("TPM_PIN_EXHAUSTED", "device", d.Path)
		}
		return lastError
	}

	return fmt.Errorf("failed to unlock after %d PIN attempts: %w", maxPINAttempts, lastError)
}

// unlockWithKey unlocks the device with a decrypted key/password.
func (d *Device) unlockWithKey(key []byte) error {
	// Try each keyslot with the key
	slots := d.dev.Slots()
	for _, slot := range slots {
		volume, err := d.dev.UnsealVolume(slot, key)
		if err != nil {
			continue
		}

		// Setup dm-crypt
		if err := d.setupDMCrypt(volume); err != nil {
			return err
		}
		return nil
	}

	return errors.New("key did not match any keyslot")
}

// UnlockWithPassphrase prompts for a passphrase and unlocks the device.
func (d *Device) UnlockWithPassphrase() error {
	for attempts := 0; attempts < 3; attempts++ {
		var passphrase string
		var err error

		if tui.IsEnabled() {
			passphrase, err = tui.PromptPassword(d.Path)
		} else {
			passphrase, err = console.ReadPassword(fmt.Sprintf("Enter passphrase for %s: ", d.Path))
		}
		if err != nil {
			return err
		}

		// Try each keyslot with the passphrase
		slots := d.dev.Slots()
		for _, slot := range slots {
			volume, err := d.dev.UnsealVolume(slot, []byte(passphrase))
			if err != nil {
				continue
			}

			// Setup dm-crypt
			if err := d.setupDMCrypt(volume); err != nil {
				if tui.IsEnabled() {
					tui.PasswordError(fmt.Sprintf("dm-crypt setup failed: %v", err))
				}
				continue
			}
			return nil
		}

		// Wrong passphrase
		if tui.IsEnabled() {
			tui.PasswordError("Incorrect passphrase, try again")
		} else {
			console.Print("luks: incorrect passphrase, try again\n")
		}
	}

	return errors.New("failed to unlock after 3 attempts")
}

// setupDMCrypt creates the dm-crypt device mapping.
func (d *Device) setupDMCrypt(volume *luks.Volume) error {
	// Use dmsetup to create the mapping
	Debug("luks: setting up dm-crypt for %s as %s\n", d.Path, d.Name)

	// The luks.go library handles dm-crypt setup internally
	if err := volume.SetupMapper(d.Name); err != nil {
		return fmt.Errorf("failed to setup mapper: %w", err)
	}

	return ensureMapperNode(d.Name)
}

// logPCRDebug logs PCR values for debugging TPM unlock failures.
func (d *Device) logPCRDebug(token *TPM2Token) {
	if len(token.PCRs) == 0 {
		return
	}

	console.DebugPrint("luks: TPM2 unlock failed - enrolled PCRs: %v (bank: %s)\n", token.PCRs, token.PCRBank)
	LogFunc("TPM_PCR_MISMATCH", "enrolled_pcrs", formatPCRList(token.PCRs), "bank", token.PCRBank)

	// Read current PCR values
	tpmClient := intpm.New()
	bank := intpm.ParsePCRBank(token.PCRBank)
	pcrValues, err := tpmClient.ReadPCRs(bank, token.PCRs)
	if err != nil {
		Debug("luks: failed to read PCR values: %v\n", err)
		return
	}

	console.DebugPrint("luks: current PCR values:\n")
	for pcr, value := range pcrValues {
		hexVal := fmt.Sprintf("%x", value)
		console.DebugPrint("  PCR %d: 0x%s\n", pcr, hexVal)
		LogFunc("TPM_PCR_VALUE", "pcr", fmt.Sprintf("%d", pcr), "value", hexVal)
	}
}

// formatTPMError converts TPM errors to user-friendly messages.
func formatTPMError(err error) string {
	if errors.Is(err, intpm.ErrWrongPIN) {
		return "Incorrect PIN"
	}
	if errors.Is(err, intpm.ErrPCRMismatch) {
		return "TPM policy mismatch - system configuration changed"
	}
	if errors.Is(err, intpm.ErrTPMLockout) {
		return "TPM locked - too many failed attempts"
	}
	if errors.Is(err, intpm.ErrTPMUnavailable) {
		return "TPM device not available"
	}
	return fmt.Sprintf("TPM unlock failed: %v", err)
}

// formatPCRList formats a list of PCRs for logging.
func formatPCRList(pcrs []int) string {
	var parts []string
	for _, pcr := range pcrs {
		parts = append(parts, fmt.Sprintf("%d", pcr))
	}
	return strings.Join(parts, ",")
}

// ensureMapperNode ensures the /dev/mapper/<name> device node exists after unlock.
func ensureMapperNode(name string) error {
	mappedPath := "/dev/mapper/" + name

	// Wait for node to appear
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(mappedPath); err == nil {
			Debug("luks: device node %s ready\n", mappedPath)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Try dmsetup mknodes as fallback
	Debug("luks: device node %s not found, trying dmsetup mknodes\n", mappedPath)
	// Note: We'll use the dmsetup binary for this since it's already in initramfs for LVM
	dmsetupPaths := []string{"/usr/sbin/dmsetup", "/sbin/dmsetup"}
	for _, dmPath := range dmsetupPaths {
		if _, err := os.Stat(dmPath); err == nil {
			// Use exec.Command and Run() to properly wait for completion (avoids zombie process)
			_ = exec.Command(dmPath, "mknodes").Run()
			break
		}
	}

	// Final check
	if _, err := os.Stat(mappedPath); err == nil {
		Debug("luks: device node %s created via dmsetup\n", mappedPath)
		return nil
	}
	return fmt.Errorf("device node %s not created", mappedPath)
}
