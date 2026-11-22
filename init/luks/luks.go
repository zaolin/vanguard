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

	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/init/recovery"
	"github.com/zaolin/vanguard/init/tui"
	lk "github.com/zaolin/vanguard/internal/luks"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// Device represents a LUKS encrypted device.
type Device struct {
	Path string
	Name string // Mapped name (e.g., "luks-sda3")
	UUID string
	dev  lk.Device
}

// Debug is set by main.go based on build tags.
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// LogFunc is a callback for boot logging.
var LogFunc func(event string, kvPairs ...string) = func(event string, kvPairs ...string) {}

// StrictMode disables passphrase fallback when TPM2 token is present.
// Always true — strict mode is the default and only mode.
// Passphrase fallback requires HOTP recovery (see init/recovery/recovery.go).
// There is no kernel cmdline override and no build-tag option.
var StrictMode bool = true

// Maximum PIN retry attempts.
const maxPINAttempts = 3

// errorMinDisplay is the minimum time a failure reason stays visible
// before the flow continues (or the TUI is torn down for recovery).
// Errors that vanish in under a second are unreadable.
const errorMinDisplay = 2 * time.Second

// recoveryStateCleared ensures the HOTP fail-count reset runs at most once
// per boot, on the first successful unlock.
var recoveryStateCleared bool

// clearRecoveryFailCount resets the persisted HOTP failure counter after a
// successful disk unlock. Failures are logged and never block boot.
func clearRecoveryFailCount() {
	client := intpm.New()
	if !client.WaitForDevice(3 * time.Second) {
		Debug("luks: recovery fail-count reset skipped (TPM unavailable)\n")
		return
	}
	recovery.ResetFailCount(client)
}

// ErrNoDevices indicates no LUKS devices were found.
var ErrNoDevices = errors.New("no LUKS devices found")

// promptForSecret reads a PIN/passphrase via the TUI when its Run loop is
// actually alive, falling back to the plain console otherwise. IsEnabled()
// is a build-tag constant — using it here instead of a runtime liveness
// check once routed every post-recovery prompt into a dead TUI where
// PromptPassword failed immediately, breaking passphrase fallback after a
// successful HOTP code.
//
// promptForSecretImpl is a package variable (not a closure) so tests can
// swap the routing logic; nil means use the default.
func promptForSecret(tuiPrompt, consolePrompt string) (string, error) {
	return promptForSecretImpl(tuiPrompt, consolePrompt)
}

// defaultPromptForSecret is the production routing.
func defaultPromptForSecret(tuiPrompt, consolePrompt string) (string, error) {
	if tuiPromptAvailable() {
		secret, err := tuiPromptPassword(tuiPrompt)
		if err == nil {
			return secret, nil
		}
		if !errors.Is(err, tui.ErrPromptUnavailable) {
			return "", err
		}
		// The TUI died between the liveness check and the prompt (e.g. the
		// user quit it mid-prompt). The console is still usable, so fall
		// back instead of failing the unlock.
	}
	return consoleReadSecret(consolePrompt)
}

// Low-level prompt seams: they let the routing itself be tested without a
// TUI or a console.
var (
	tuiPromptAvailable = tui.PromptAvailable
	tuiPromptPassword  = tui.PromptPassword
	tuiPromptRetry     = tui.PasswordErrorWithRetry
	consoleReadSecret  = console.ReadPassword
)

var promptForSecretImpl = defaultPromptForSecret

// showAndDwellError displays a terminal TPM failure reason and keeps it on
// screen for at least errorMinDisplay before continuing (recovery flow or
// halt). In TUI mode the error renders in the TUI while it is still live;
// otherwise it is printed to the console.
func showAndDwellError(msg string) {
	if tui.PromptAvailable() {
		tui.ShowTPMError(msg)
	} else {
		console.Print("luks: %s\n", msg)
	}
	time.Sleep(errorMinDisplay)
}

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

	// One PIN attempt budget for the whole TPM, shared across all
	// devices: the TPM's dictionary-attack counter is per-TPM (typically 3
	// tries), so a per-device budget would let a mistyped PIN on two
	// volumes lock the TPM out.
	attemptsLeft := maxPINAttempts

	for _, dev := range devices {
		// Measure the LUKS header into PCR 11 before unlocking.
		// This binds the pcrlock policy to the on-disk LUKS header state.
		//
		// Only measure devices the policy actually covers — i.e. those
		// with a pcrlock token. Extending PCR 11 for a device outside the
		// policy (a passphrase-only data disk, an encrypted USB stick)
		// shifts the PCR 11 hash chain for every device measured after it
		// and makes the protected device's unseal fail.
		//
		// Skip in test mode (no TPM available in QEMU coverage tests).
		if !isTestMode() && dev.HasPCRLockToken() {
			if err := dev.MeasureHeader(); err != nil {
				Debug("luks: header measurement failed for %s: %v (continuing)\n", dev.Path, err)
			}
		}

		Debug("luks: unlocking %s\n", dev.Path)
		if err := dev.Unlock(&attemptsLeft); err != nil {
			// Close device on error before returning
			dev.Close()
			return false, fmt.Errorf("failed to unlock %s: %w", dev.Path, err)
		}
		// Close device after successful unlock to free resources
		// The dm-crypt mapping remains active after Close()
		dev.Close()

		// A successful unlock proves the legitimate holder is present:
		// clear the persisted HOTP failure counter so earlier typos do not
		// count against future recovery attempts. Non-fatal; skipped in
		// test mode (coverage runs have no recovery state to reset).
		if !isTestMode() && !recoveryStateCleared {
			recoveryStateCleared = true
			clearRecoveryFailCount()
		}
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
	dev, err := lk.Open(path)
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
// Unlock attempts to unlock the LUKS device.
//
// attemptsLeft is the shared PIN attempt budget for the whole TPM (the
// dictionary-attack counter is per-TPM, not per-device). A nil pointer
// means "use a fresh budget" — only correct for a single-device unlock.
func (d *Device) Unlock(attemptsLeft *int) error {
	// Check if already unlocked
	mappedPath := "/dev/mapper/" + d.Name
	if _, err := os.Stat(mappedPath); err == nil {
		Debug("luks: %s already unlocked\n", d.Path)
		return nil
	}

	// Check for systemd-tpm2 tokens
	if d.HasTPM2Token() {
		console.DebugPrint("luks: found TPM2 token on %s, trying token unlock\n", d.Path)
		err := d.UnlockWithTPM2(attemptsLeft)

		if err == nil {
			console.DebugPrint("luks: %s unlocked with TPM2 token\n", d.Path)
			LogFunc("LUKS_UNLOCK", "device", d.Path, "method", "token", "status", "ok")
			return nil
		}

		console.DebugPrint("luks: TPM2 unlock failed: %v\n", err)

		// Show the classified reason while the TUI is still up, and keep
		// it on screen long enough to read. Without this, the TUI was
		// torn down immediately and the reason never became visible.
		showAndDwellError(formatTPMError(err))

		// Strict mode: try HOTP recovery before halting
		if StrictMode {
			// Quit TUI so console prompts are visible for HOTP recovery
			if tui.PromptAvailable() {
				tui.Quit()
				tui.ForceReset()
			}
			// Attempt HOTP recovery — if successful, enable passphrase fallback
			// for this boot only
			tpmClient := intpm.New()
			if recovery.TryHOTP(tpmClient, d.Path) {
				console.Print("luks: HOTP recovery accepted, passphrase fallback enabled\n")
				LogFunc("RECOVERY_SUCCESS", "device", d.Path, "method", "hotp")
				// Fall through to passphrase fallback below
			} else {
				console.Print("luks: strict mode - no passphrase fallback\n")
				LogFunc("LUKS_FAIL", "device", d.Path, "method", "token",
					"error", err.Error(), "mode", "strict")
				return fmt.Errorf("token unlock failed (strict mode): %w", err)
			}
		}

		// Normal mode or HOTP recovery succeeded: fall back to passphrase.
		// The TPM failure reason was already shown (and dwelled on) before
		// the HOTP prompt; do not re-print the stale error here.
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

// HasPCRLockToken checks if the device has a systemd-tpm2 token that uses
// the pcrlock policy.
//
// Only such devices are bound by the policy's PCR 11 (LUKS header)
// prediction. Extending PCR 11 for a device the policy does not cover
// (e.g. a passphrase-only data disk, or a USB stick that happens to be
// LUKS-encrypted) shifts the PCR 11 hash chain and makes the booted
// value differ from the predicted one — the protected device then fails
// to unseal even though nothing about it changed.
func (d *Device) HasPCRLockToken() bool {
	tokens, err := d.dev.Tokens()
	if err != nil {
		return false
	}

	for _, token := range tokens {
		if token.Type != "systemd-tpm2" {
			continue
		}
		parsed, err := ParseTPM2Token(token)
		if err != nil {
			continue
		}
		if parsed.UsePCRLock {
			return true
		}
	}
	return false
}

// GetTPM2Tokens returns all systemd-tpm2 tokens in header order. Some
// systems carry more than one (e.g. an old direct-PCR token plus a newer
// pcrlock token); only trying the first silently breaks unlock even
// though a valid token exists.
func (d *Device) GetTPM2Tokens() ([]*TPM2Token, error) {
	tokens, err := d.dev.Tokens()
	if err != nil {
		return nil, err
	}

	var result []*TPM2Token
	var parseErr error
	for _, token := range tokens {
		if token.Type != "systemd-tpm2" {
			continue
		}
		parsed, err := ParseTPM2Token(token)
		if err != nil {
			Debug("luks: skipping unparseable systemd-tpm2 token %d: %v\n", token.ID, err)
			parseErr = fmt.Errorf("systemd-tpm2 token %d: %w", token.ID, err)
			continue
		}
		result = append(result, parsed)
	}
	if len(result) == 0 {
		if parseErr != nil {
			// A corrupt token is not "no token": report the corruption so
			// the diagnostic (e.g. a malformed NV binding) is preserved.
			return nil, parseErr
		}
		return nil, errors.New("no systemd-tpm2 token found")
	}
	return result, nil
}

// UnlockWithTPM2 attempts to unlock using the TPM2 token.
//
// attemptsLeft is the shared PIN attempt budget for the whole TPM; nil
// means a fresh budget for this call.
func (d *Device) UnlockWithTPM2(attemptsLeft *int) error {
	if attemptsLeft == nil {
		budget := maxPINAttempts
		attemptsLeft = &budget
	}
	// Wait for TPM device. 10s budget: on cold boot some fTPMs (SPI/I2C
	// bus) enumerate noticeably later than the disk; a 3s wait made the
	// unlock "directly stop" with TPM unavailable on such hardware.
	tpmClient := intpm.New()
	if !tpmClient.WaitForDevice(10 * time.Second) {
		return fmt.Errorf("%w", intpm.ErrTPMUnavailable)
	}

	// Check lockout status. If the read fails, treat it as a potential
	// lockout — proceeding could burn additional DA counter slots.
	status, err := tpmClient.GetLockoutStatus()
	if err != nil {
		LogFunc("TPM_LOCKOUT_READ_FAILED", "device", d.Path, "error", err.Error())
		return fmt.Errorf("failed to read TPM lockout status: %w", err)
	}
	if status.InLockout {
		msg := "TPM locked - too many failed attempts"
		hint := ""
		if status.LockoutRecovery > 0 {
			hint = fmt.Sprintf("Wait %d seconds or reboot to clear lockout", status.LockoutRecovery)
		}
		// Keep the lockout screen up long enough to read the hint.
		if tui.PromptAvailable() {
			tui.ShowTPMLockout(msg, hint)
		} else {
			console.Print("luks: %s\n", msg)
			if hint != "" {
				console.Print("luks: %s\n", hint)
			}
		}
		time.Sleep(errorMinDisplay)
		LogFunc("TPM_LOCKOUT", "device", d.Path, "hint", hint)
		return intpm.ErrTPMLockout
	}

	// Get all systemd-tpm2 tokens and try each in header order
	tokens, err := d.GetTPM2Tokens()
	if err != nil {
		return err
	}

	// Test hook: force token-unseal failure to exercise the HOTP recovery
	// path end-to-end in QEMU (vanguard.testmode=1 vanguard.testhotp=1).
	// Returns a forced error so the normal strict-mode failure path in
	// Unlock() continues into HOTP recovery.
	if testForceHOTP() {
		Debug("luks: test mode: forcing TPM2 unseal failure for HOTP recovery test\n")
		LogFunc("TPM_TEST_FORCED_FAIL", "device", d.Path)
		return errForcedHOTP
	}

	// Detect TPM2 token strategy (pcrlock.json policy is shared across tokens)
	detection, _ := DetectTPM2TokenStrategy(d.Path)
	var pcrlockPolicy *intpm.PCRLockPolicy
	if detection != nil {
		Debug("luks: TPM2 token strategy: %v\n", detection.Strategy)
		pcrlockPolicy = detection.PCRLockPolicy
	}

	// Shared PIN attempt budget across all tokens AND devices: the TPM's
	// dictionary-attack counter is per-TPM (typically 3 tries), so a
	// per-token or per-device budget could lock the TPM out from a single
	// typo on a multi-volume system.
	return d.tryTokens(tpmClient, tokens, pcrlockPolicy, attemptsLeft)
}

// Token-unlock seams: they let the token loop be tested without a TPM or a
// LUKS device. Production uses the real implementations.
var (
	nvReadPublic = func(tpmClient *intpm.Client, index uint32) error {
		_, err := tpmClient.NVReadPublic(index)
		return err
	}
	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return tpmClient.GetLockoutStatus()
	}
	unlockTokenPIN   = (*Device).unlockWithTPM2PIN
	unlockTokenNoPIN = (*Device).unlockWithTPM2NoPIN
)

// errLockoutUnknown marks a failure to read the TPM's lockout state after a
// failed PIN attempt. Safety-relevant: without it the user would only see a
// wrong-PIN message while the real problem is that further attempts may lock
// the TPM.
var errLockoutUnknown = errors.New("the TPM lockout state could not be read")

// tokenErrorPriority ranks token failures by how actionable they are. Only one
// reason is shown to the user, and the most useful one must not be drowned out
// by a later, less specific failure on another token.
func tokenErrorPriority(err error) int {
	switch {
	case errors.Is(err, intpm.ErrTPMLockout):
		return 4 // the TPM is locked out — recovery guidance, not a retry
	case errors.Is(err, intpm.ErrTokenStaleNVIndex):
		return 3 // re-enrollment required — the root cause
	case errors.Is(err, errLockoutUnknown):
		return 2 // the TPM state is unknown — safety-relevant
	default:
		return 1
	}
}

// tryTokens attempts each systemd-tpm2 token in order until one unlocks the
// device.
//
// attemptsLeft is the shared PIN attempt budget for the whole TPM, not a
// per-token budget: the TPM's dictionary-attack counter is per-TPM.
//
// The most actionable failure is reported (see tokenErrorPriority); ties keep
// the first error, which is the root cause rather than its consequences.
func (d *Device) tryTokens(tpmClient *intpm.Client, tokens []*TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy, attemptsLeft *int) error {
	var lastErr error
	recordFailure := func(err error) {
		if err == nil {
			return
		}
		if lastErr == nil || tokenErrorPriority(err) > tokenErrorPriority(lastErr) {
			lastErr = err
		}
	}

	for _, token := range tokens {
		Debug("luks: trying systemd-tpm2 token %d (pin=%v, pcrlock=%v)\n",
			token.ID, token.NeedsPIN, token.UsePCRLock)

		// A token whose pcrlock NV index is gone can never unseal: the
		// sealed blob binds that index's NV name. Skip it BEFORE asking
		// for a PIN (prompting would burn dictionary-attack slots for an
		// attempt that cannot succeed) — but keep trying the other
		// tokens: one stale token must not block a valid second token.
		if token.UsePCRLock && token.PCRLockNV != 0 {
			if err := nvReadPublic(tpmClient, token.PCRLockNV); err != nil {
				if !intpm.IsNVIndexMissing(err) {
					// A transient TPM error is not a missing index; let
					// the unseal attempt report the real error.
					Debug("luks: NVReadPublic(0x%x) failed: %v\n", token.PCRLockNV, err)
				} else {
					Debug("luks: token %d pins missing NV index 0x%x, skipping it\n", token.ID, token.PCRLockNV)
					recordFailure(fmt.Errorf("%w: index 0x%x is missing from the TPM (the policy was regenerated at a different index) — re-enroll the token: vanguard enroll -u <uki> -l %s",
						intpm.ErrTokenStaleNVIndex, token.PCRLockNV, d.Path))
					continue
				}
			}
		}

		// The shared PIN budget gates PIN-bearing tokens only: a PIN-less
		// token consumes no dictionary-attack attempt, so it must still
		// be tried when the budget is spent.
		if token.NeedsPIN && *attemptsLeft <= 0 {
			Debug("luks: skipping PIN token %d — the shared PIN budget is spent\n", token.ID)
			recordFailure(errPINBudgetExhausted)
			continue
		}

		var err error
		if token.NeedsPIN {
			err = unlockTokenPIN(d, tpmClient, token, pcrlockPolicy, attemptsLeft)
		} else {
			err = unlockTokenNoPIN(d, tpmClient, token, pcrlockPolicy)
		}
		if err == nil {
			return nil
		}
		recordFailure(err)
		Debug("luks: token %d failed: %v\n", token.ID, err)
		// A cancelled PIN prompt stops the whole token loop rather than
		// re-prompting per token.
		if errors.Is(err, errPINCancelled) {
			return err
		}
		// A real lockout reported by the unseal itself also stops the loop:
		// another token would only make it worse, and the user needs the
		// lockout/recovery guidance, not a re-enroll hint.
		if errors.Is(err, intpm.ErrTPMLockout) {
			return err
		}

		// Re-check the TPM's own dictionary-attack counter before the
		// next PIN token: if the previous token's attempts brought the
		// TPM close to its limit, the next attempt would lock it out.
		if token.NeedsPIN {
			status, err := lockoutStatus(tpmClient)
			if err != nil {
				// The lockout state is unknown: issuing another PIN
				// authorization could drive the TPM into lockout. Stop
				// PIN attempts; PIN-less tokens are still tried.
				*attemptsLeft = 0
				recordFailure(fmt.Errorf("%w after a failed PIN attempt: %v", errLockoutUnknown, err))
				continue
			}
			if status.InLockout {
				Debug("luks: TPM entered lockout after previous token attempt\n")
				return intpm.ErrTPMLockout
			}
		}
	}
	return lastErr
}

// errForcedHOTP is returned by the vanguard.testhotp=1 test hook so the
// normal strict-mode failure path exercises HOTP recovery end-to-end.
var errForcedHOTP = errors.New("test-forced token unseal failure")

// errPINCancelled is returned when the user cancelled the TUI PIN prompt
// (ctrl+c). Distinct sentinel so the multi-token loop can stop instead of
// re-prompting for every remaining token.
var errPINCancelled = errors.New("PIN entry cancelled")

// errPINBudgetExhausted is returned when the shared PIN attempt budget is
// spent. It names the TPM dictionary-attack limit so the user understands
// why no further prompt appears (and that waiting is the remedy, not another
// retry).
var errPINBudgetExhausted = errors.New("PIN attempt budget exhausted — the TPM dictionary-attack limit would be exceeded")

// unlockWithTPM2NoPIN attempts TPM2 unlock without PIN.
func (d *Device) unlockWithTPM2NoPIN(tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy) error {
	password, err := token.Unseal(tpmClient, nil, pcrlockPolicy)
	if err != nil {
		d.logPCRDebug(token)
		return err
	}

	return d.unlockWithKeyForToken(password, token)
}

// unsealWithPIN performs the TPM unseal with the given PIN. It is a
// package variable so the PIN attempt budget can be tested without a TPM.
var unsealWithPIN = func(token *TPM2Token, tpmClient *intpm.Client, pin []byte, pcrlockPolicy *intpm.PCRLockPolicy) ([]byte, error) {
	return token.Unseal(tpmClient, pin, pcrlockPolicy)
}

// unlockWithTPM2PIN attempts TPM2 unlock with PIN and retry logic.
//
// attemptsLeft is a SHARED budget across all tokens AND devices: the TPM
// dictionary-attack counter is per-TPM, not per-token, and typical TPMs
// allow only 3 failed auth attempts (TPM2B_DEFAULT maxTries=3) before
// locking out for a long recovery period. A per-token budget of 3 would
// allow 3*N attempts (6 with two tokens) and lock the TPM from a single
// mistyped PIN. The budget is decremented by every real unseal attempt.
// A nil budget means "use a fresh budget for this call".
func (d *Device) unlockWithTPM2PIN(tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy, attemptsLeft *int) error {
	if attemptsLeft == nil {
		budget := maxPINAttempts
		attemptsLeft = &budget
	}

	var lastError error
	var pin string
	var err error

	// Zero the PIN string's backing buffer after use to reduce the cold-boot
	// PIN extraction window (console.ZeroString). This is best-effort — the
	// GC may have copied the string, and the TUI may retain its own copy.
	// Still better than leaving it in heap indefinitely.
	defer console.ZeroString(&pin)

	// Prompt for PIN
	promptForPIN := func() (string, error) {
		return promptForSecret(d.Path+" (TPM PIN)", fmt.Sprintf("Enter TPM2 PIN for %s: ", d.Path))
	}

	for attempt := 1; attempt <= maxPINAttempts; attempt++ {
		if *attemptsLeft <= 0 {
			// Shared budget exhausted (another token or device used it
			// up) — stop prompting rather than risking a TPM lockout.
			return errPINBudgetExhausted
		}
		// Prompt for PIN
		if attempt == 1 {
			// In test mode, auto-enter PIN from kernel cmdline (vanguard.testpin=)
			testPin := getTestPin()
			if testPin != "" {
				pin = testPin
				Debug("luks: using test PIN from cmdline\n")
			} else {
				pin, err = promptForPIN()
			}
		}

		if err != nil {
			tui.PasswordPromptDone()
			return fmt.Errorf("failed to read PIN: %w", err)
		}

		// An empty PIN from the TUI is a user cancel (ctrl+c sends ""),
		// not a real attempt. Unsealing with an empty auth value would
		// burn a dictionary-attack counter slot for nothing.
		if pin == "" {
			tui.PasswordPromptDone()
			LogFunc("TPM_PIN_CANCELLED", "device", d.Path, "attempt", fmt.Sprintf("%d", attempt))
			return fmt.Errorf("%w", errPINCancelled)
		}

		// Unseal with PIN using native TPM implementation. This is a real
		// authentication attempt — consume one unit of the shared
		// dictionary-attack budget before trying.
		*attemptsLeft--
		password, unsealErr := unsealWithPIN(token, tpmClient, []byte(pin), pcrlockPolicy)
		if unsealErr == nil {
			// Success - unlock with password
			tui.PasswordPromptDone()
			return d.unlockWithKeyForToken(password, token)
		}

		// Classify error
		userMsg := formatTPMError(unsealErr)
		lastError = unsealErr

		// Check if retryable
		// For pcrlock tokens, ErrPolicyFailed collapses both wrong-PIN and
		// wrong-PCR into one error — retry anyway since the user might just
		// have a wrong PIN. The shared budget (and the TPM's own DA
		// counter) still caps the total number of attempts.
		if (errors.Is(unsealErr, intpm.ErrWrongPIN) || errors.Is(unsealErr, intpm.ErrPolicyFailed)) &&
			attempt < maxPINAttempts && *attemptsLeft > 0 {
			LogFunc("TPM_PIN_FAIL", "device", d.Path, "attempt", fmt.Sprintf("%d", attempt))
			if errors.Is(unsealErr, intpm.ErrPolicyFailed) {
				userMsg = fmt.Sprintf("TPM unlock failed (attempt %d of %d)", attempt, maxPINAttempts)
			} else {
				userMsg = fmt.Sprintf("Incorrect PIN (attempt %d of %d)", attempt, maxPINAttempts)
			}
			if tuiPromptAvailable() {
				pin, err = tuiPromptRetry(userMsg)
				if errors.Is(err, tui.ErrPromptUnavailable) {
					// The TUI exited while waiting after a wrong PIN:
					// fall back to the console instead of aborting the
					// unlock with a prompt error.
					console.Print("luks: %s\n", userMsg)
					pin, err = promptForPIN()
				}
			} else {
				console.Print("luks: %s\n", userMsg)
				pin, err = promptForPIN()
			}
			continue
		}

		// Non-retryable or last attempt
		if tui.PromptAvailable() {
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
			// Keep the reason on screen before the caller tears the TUI
			// down for recovery — sub-second errors are unreadable.
			time.Sleep(errorMinDisplay)
		} else {
			console.Print("luks: %s\n", userMsg)
		}

		if !errors.Is(unsealErr, intpm.ErrWrongPIN) && !errors.Is(unsealErr, intpm.ErrPolicyFailed) {
			d.logPCRDebug(token)
			LogFunc("TPM_ERROR", "device", d.Path, "message", userMsg)
		} else {
			LogFunc("TPM_PIN_EXHAUSTED", "device", d.Path)
		}
		return lastError
	}

	return fmt.Errorf("failed to unlock after %d PIN attempts: %w", maxPINAttempts, lastError)
}

// unlockWithKeyForToken unlocks the device using only the keyslots assigned to a specific TPM2 token.
func (d *Device) unlockWithKeyForToken(key []byte, token *TPM2Token) error {
	slots := token.Keyslots
	if len(slots) == 0 {
		// Fallback: try all slots if token doesn't specify which keyslots
		Debug("luks: token has no keyslots, trying all %d available\n", len(d.dev.Slots()))
		slots = d.dev.Slots()
	}
	Debug("luks: unlockWithKeyForToken: %d token keyslots (%v), key length=%d\n", len(slots), slots, len(key))
	for _, slot := range slots {
		volume, err := d.dev.UnsealVolume(slot, key)
		if err != nil {
			Debug("luks: keyslot %d: UnsealVolume failed: %v\n", slot, err)
			continue
		}
		Debug("luks: keyslot %d: UnsealVolume succeeded\n", slot)

		if err := d.setupDMCrypt(volume); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("key did not match any of the token's keyslots %v", slots)
}

// UnlockWithPassphrase prompts for a passphrase and unlocks the device.
func (d *Device) UnlockWithPassphrase() error {
	logKeymapStatus()

	for attempts := 0; attempts < 3; attempts++ {
		var passphrase string
		var err error

		// In test mode, auto-enter the passphrase from the kernel cmdline
		// (vanguard.testpass=) — mirrors the vanguard.testpin= hook.
		if testPass := getTestPass(); testPass != "" {
			passphrase = testPass
			Debug("luks: using test passphrase from cmdline\n")
		} else {
			passphrase, err = promptForSecret(d.Path, fmt.Sprintf("Enter passphrase for %s: ", d.Path))
		}
		if err != nil {
			return err
		}

		Debug("passphrase: entered %d bytes\n", len(passphrase))

		// Try each keyslot with the passphrase
		slots := d.dev.Slots()
		Debug("passphrase: trying %d keyslots\n", len(slots))
		for _, slot := range slots {
			volume, err := d.dev.UnsealVolume(slot, []byte(passphrase))
			if err != nil {
				Debug("passphrase: keyslot %d failed: %v\n", slot, err)
				continue
			}
			Debug("passphrase: keyslot %d succeeded\n", slot)

			// Setup dm-crypt
			if err := d.setupDMCrypt(volume); err != nil {
				msg := fmt.Sprintf("dm-crypt setup failed: %v", err)
				if tui.PromptAvailable() {
					tui.PasswordError(msg)
				} else {
					console.Print("luks: %s\n", msg)
				}
				continue
			}
			return nil
		}

		// Wrong passphrase
		if tui.PromptAvailable() {
			tui.PasswordError("Incorrect passphrase, try again")
		} else {
			console.Print("luks: incorrect passphrase, try again\n")
		}
	}

	return errors.New("failed to unlock after 3 attempts")
}

// setupDMCrypt creates the dm-crypt device mapping.
func (d *Device) setupDMCrypt(volume *lk.Volume) error {
	// Use dmsetup to create the mapping
	Debug("luks: setting up dm-crypt for %s as %s\n", d.Path, d.Name)

	// The luks.go library handles dm-crypt setup internally
	if err := volume.SetupMapper(d.Name); err != nil {
		return fmt.Errorf("failed to setup mapper: %w", err)
	}

	return ensureMapperNode(d.Name)
}

// logKeymapStatus logs the current keyboard layout status for diagnosing
// passphrase failures. Checks /etc/vconsole.conf for the configured keymap
// and whether the loadkeys binary exists in the initramfs.
func logKeymapStatus() {
	keymap := ""
	if data, err := os.ReadFile("/etc/vconsole.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "KEYMAP=") {
				keymap = strings.Trim(strings.TrimPrefix(line, "KEYMAP="), "\"'")
				break
			}
		}
	}

	loadkeysExists := false
	for _, p := range []string{"/usr/bin/loadkeys", "/bin/loadkeys"} {
		if _, err := os.Stat(p); err == nil {
			loadkeysExists = true
			break
		}
	}

	keymapDirExists := false
	for _, d := range []string{"/usr/share/kbd/keymaps", "/lib/kbd/keymaps", "/usr/lib/kbd/keymaps"} {
		if _, err := os.Stat(d); err == nil {
			keymapDirExists = true
			break
		}
	}

	Debug("passphrase: keymap status: configured=%q, loadkeys=%v, keymap_dir=%v\n",
		keymap, loadkeysExists, keymapDirExists)
	LogFunc("KEYMAP_STATUS", "configured", keymap,
		"loadkeys", fmt.Sprintf("%v", loadkeysExists),
		"keymap_dir", fmt.Sprintf("%v", keymapDirExists))
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
//
// The stale-NV-index error carries actionable remediation (re-enroll the
// token) and must NOT be collapsed into the generic "TPM unlock failed"
// message — otherwise the user gets no explanation for a boot that
// suddenly requires HOTP recovery.
func formatTPMError(err error) string {
	if errors.Is(err, intpm.ErrTokenStaleNVIndex) {
		return err.Error()
	}
	if errors.Is(err, intpm.ErrPolicyFailed) {
		return "TPM unlock failed"
	}
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

// getTestPin reads the test PIN from the kernel cmdline (vanguard.testpin=).
// Returns empty string if not set.
func getTestPin() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, param := range strings.Fields(string(data)) {
		if strings.HasPrefix(param, "vanguard.testpin=") {
			return strings.TrimPrefix(param, "vanguard.testpin=")
		}
	}
	return ""
}

// getTestPass reads the test LUKS passphrase from the kernel cmdline
// (vanguard.testpass=). Returns empty string if not set. Only honored in
// test mode.
func getTestPass() string {
	if !isTestMode() {
		return ""
	}
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, param := range strings.Fields(string(data)) {
		if strings.HasPrefix(param, "vanguard.testpass=") {
			return strings.TrimPrefix(param, "vanguard.testpass=")
		}
	}
	return ""
}

// testForceHOTP checks the kernel cmdline for vanguard.testhotp=1. Only
// honored in test mode: when set, the TPM2 unseal path fails unconditionally
// so the HOTP recovery flow is exercised in QEMU tests.
func testForceHOTP() bool {
	if !isTestMode() {
		return false
	}
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "vanguard.testhotp=1")
}

// isTestMode checks the kernel command line for vanguard.testmode=1.
func isTestMode() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "vanguard.testmode=1")
}
