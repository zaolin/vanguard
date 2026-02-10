package cryptsetup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/init/tui"
)

// Cryptsetup binary paths
var cryptsetupPaths = []string{
	"/usr/bin/cryptsetup",
	"/usr/sbin/cryptsetup",
	"/sbin/cryptsetup",
	"/bin/cryptsetup",
}

var cryptsetupBin string

// Debug function placeholder - will be set by the main init package
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// LogFunc is a callback for boot logging - will be set by the main init package
// Parameters: event string, key-value pairs
var LogFunc func(event string, kvPairs ...string) = func(event string, kvPairs ...string) {}

// StrictMode is set by main.go based on build tags
// When true, no passphrase fallback is allowed after token failure
var StrictMode bool = false

// Maximum PIN retry attempts before giving up
const maxPINAttempts = 3

// TPMErrorType classifies TPM unlock failures
type TPMErrorType int

const (
	TPMErrorUnknown      TPMErrorType = iota
	TPMErrorWrongPIN                  // 0x98e/0x984/0x985/0x9a2/0x22e - auth HMAC failed, retryable
	TPMErrorPCRMismatch               // 0x99d/0x98d/0x2c4/0x2c5 - policy check failed, not recoverable
	TPMErrorLockout                   // 0x921/0x923 - DA lockout active
	TPMErrorUnavailable               // TPM device not found
	TPMErrorInvalidParam              // 0x1c4 - value out of range (policy misconfigured)
	TPMErrorCommunication             // TSS2/ESAPI/TCTI communication errors (0x60000+, 0x70000+, 0xA0000+)
	TPMErrorBadAuth                   // 0x9a2/0x923 - authorization failed (may be retryable)
	TPMErrorHandleInvalid             // 0x902 - invalid handle/session
)

// classifyTPMError analyzes tpm2-tss stderr output to determine error type
// tpm2-tss outputs errors to stderr by default (see TSS2_LOGFILE env var)
//
// TPM Response Codes (TPM_RC):
//   - FMT0 errors (0x000-0x3BF): Simple error codes
//   - FMT1 errors (0x800-0xBFF): Format 1 with session/parameter/handle info
//   - Warning codes (0xC00-0xFFF): Warning level responses
//
// Common codes from cryptsetup + libcryptsetup tpm2 plugin:
//   0x98e = TPM_RC_AUTH_FAIL (FMT1, session 1)
//   0x984 = TPM_RC_AUTH_UNTESTED (FMT1, session 1)
//   0x985 = TPM_RC_AUTH_FAIL variant (FMT1, session 1)
//   0x99d = TPM_RC_POLICY_FAIL (FMT1, session 1)
//   0x98d = TPM_RC_POLICY_FAIL (FMT1, session 1, alternate)
//   0x921 = TPM_RC_LOCKOUT (warning)
//   0x923 = TPM_RC_BAD_AUTH (warning)
//   0x9a2 = TPM_RC_BAD_AUTH (FMT1, session 1)
//   0x902 = TPM_RC_HANDLE (FMT1, session 1) - invalid handle
//   0x1c4 = TPM_RC_VALUE - parameter out of range
//   0x184 = TPM_RC_FAILURE - general failure
//
// TSS2 Layer errors (upper bits indicate layer):
//   0x60000+ = FAPI layer errors
//   0x70000+ = ESAPI layer errors
//   0x80000+ = SYS layer errors
//   0xA0000+ = TCTI layer errors
func classifyTPMError(stderr string) TPMErrorType {
	lower := strings.ToLower(stderr)

	// Helper to check for TPM error codes in both short (0x98e) and long (0x0000098e) formats
	hasErrorCode := func(code string) bool {
		// Check short format (e.g., 0x98e)
		if strings.Contains(lower, code) {
			return true
		}
		// Check long format with leading zeros (e.g., 0x0000098e)
		// Convert short code like "0x98e" to "0x0000098e"
		if len(code) > 2 {
			hexPart := code[2:] // Remove "0x" prefix
			longForm := "0x" + strings.Repeat("0", 8-len(hexPart)) + hexPart
			if strings.Contains(lower, longForm) {
				return true
			}
		}
		return false
	}

	// === LOCKOUT ERRORS (checked first - most severe) ===
	// TPM_RC_LOCKOUT (0x921) - Dictionary Attack lockout active
	// "tpm:warn(2):authorizations for objects subject to DA protection are not allowed"
	// Also check for 0x923 (TPM_RC_BAD_AUTH as warning)
	if hasErrorCode("0x921") ||
		hasErrorCode("0x923") ||
		strings.Contains(lower, "da protection") ||
		strings.Contains(lower, "in lockout") ||
		strings.Contains(lower, "dictionary attack") {
		return TPMErrorLockout
	}

	// === AUTHORIZATION/PIN ERRORS (retryable) ===
	// TPM_RC_AUTH_FAIL variants (FMT1 with session info)
	// 0x98e: "tpm:session(1):the authorization HMAC check failed and DA counter incremented"
	// 0x984: TPM_RC_AUTH_UNTESTED
	// 0x985: Auth fail variant
	// 0x9a2: TPM_RC_BAD_AUTH (FMT1)
	// 0x22e: TPM_RC_BAD_AUTH (base code)
	if hasErrorCode("0x98e") ||
		hasErrorCode("0x984") ||
		hasErrorCode("0x985") ||
		hasErrorCode("0x9a2") ||
		hasErrorCode("0x22e") ||
		strings.Contains(lower, "authorization hmac check failed") ||
		strings.Contains(lower, "da counter incremented") ||
		strings.Contains(lower, "authorization failed") ||
		strings.Contains(lower, "bad auth") ||
		strings.Contains(lower, "bad pin") ||
		strings.Contains(lower, "auth fail") {
		return TPMErrorWrongPIN
	}

	// === PCR POLICY ERRORS (not retryable) ===
	// TPM_RC_POLICY_FAIL (FMT1 with session)
	// 0x99d: "tpm:session(1):a policy check failed"
	// 0x98d: Alternate policy fail code
	// 0x2c4: TPM_RC_POLICY_CC (command code policy)
	// 0x2c5: TPM_RC_POLICY_RC (response code policy)
	if hasErrorCode("0x99d") ||
		hasErrorCode("0x98d") ||
		hasErrorCode("0x2c4") ||
		hasErrorCode("0x2c5") ||
		strings.Contains(lower, "policy check failed") ||
		strings.Contains(lower, "policy digest mismatch") ||
		strings.Contains(lower, "pcr mismatch") ||
		strings.Contains(lower, "policy authorization failed") {
		return TPMErrorPCRMismatch
	}

	// === HANDLE/SESSION ERRORS ===
	// 0x902: TPM_RC_HANDLE (FMT1) - invalid handle or session
	// May indicate stale session or handle not found
	if hasErrorCode("0x902") ||
		strings.Contains(lower, "handle") && strings.Contains(lower, "invalid") ||
		strings.Contains(lower, "session") && strings.Contains(lower, "invalid") {
		return TPMErrorHandleInvalid
	}

	// === INVALID PARAMETER ERRORS ===
	// TPM_RC_VALUE (0x1c4) - parameter out of range
	// TPM_RC_HIERARCHY (0x1c5) - invalid hierarchy
	// TPM_RC_KEY_SIZE (0x1c6) - bad key size
	// TPM_RC_MGF (0x1d5) - invalid MGF
	if hasErrorCode("0x1c4") ||
		hasErrorCode("0x1c5") ||
		hasErrorCode("0x1c6") ||
		hasErrorCode("0x1d5") ||
		strings.Contains(lower, "value is out of range") ||
		strings.Contains(lower, "not correct for the context") ||
		strings.Contains(lower, "invalid parameter") {
		return TPMErrorInvalidParam
	}

	// === TSS2 LAYER ERRORS (communication/protocol) ===
	// Only check for TSS2 errors if no specific TPM response code was found above.
	// ESAPI errors (0x70000 range)
	// TCTI errors (0xA0000 range) - transport/communication
	// SYS errors (0x80000 range)
	// FAPI errors (0x60000 range)
	// Check for hex error codes in TSS2 layer ranges (must be 6+ digits to avoid matching line numbers)
	tss2Pattern := regexp.MustCompile(`0x[0-9a-fA-F]{6,}`)
	for _, match := range tss2Pattern.FindAllString(lower, -1) {
		if hexVal, err := strconv.ParseInt(match, 0, 64); err == nil {
			// Check layer bits (bits 16-23 indicate the layer)
			layer := (hexVal >> 16) & 0xFF
			switch layer {
			case 0x06: // FAPI layer
				return TPMErrorCommunication
			case 0x07: // ESAPI layer
				return TPMErrorCommunication
			case 0x08: // SYS layer
				return TPMErrorCommunication
			case 0x0A: // TCTI layer
				return TPMErrorCommunication
			}
		}
	}
	// Check for actual communication failure patterns (not source file paths)
	// These indicate transport/connection issues, not TPM command failures
	if strings.Contains(lower, "tcti") && (strings.Contains(lower, "io error") ||
		strings.Contains(lower, "no connection") ||
		strings.Contains(lower, "connection refused")) ||
		strings.Contains(lower, "communication") && strings.Contains(lower, "failed") ||
		strings.Contains(lower, "device not found") && strings.Contains(lower, "tpm") {
		return TPMErrorCommunication
	}

	// === CRYPTSETUP SPECIFIC ERRORS ===
	// These come from libcryptsetup's token plugin interface
	if strings.Contains(lower, "token failed") ||
		strings.Contains(lower, "tpm2 token") && strings.Contains(lower, "fail") ||
		strings.Contains(lower, "plugin failed") {
		// Check if it's a specific TPM error wrapped by cryptsetup
		if strings.Contains(lower, "pin") || strings.Contains(lower, "password") {
			return TPMErrorWrongPIN
		}
		if strings.Contains(lower, "pcr") {
			return TPMErrorPCRMismatch
		}
	}

	// === GENERAL TPM FAILURE ===
	// TPM_RC_FAILURE (0x184) - nonspecific failure
	if strings.Contains(lower, "0x184") ||
		strings.Contains(lower, "tpm failure") ||
		strings.Contains(lower, "command failed") {
		return TPMErrorUnknown
	}

	return TPMErrorUnknown
}

// isRetryableTPMError returns true if the error type allows retry
// For PIN mode, we retry on wrong PIN and unknown errors (give user benefit of doubt)
// Non-retryable: PCR mismatch (system changed), lockout (wait required),
//   invalid param (config error), unavailable (TPM missing)
// Retryable: Wrong PIN (try again), communication (transient), handle (may resolve)
func isRetryableTPMError(errType TPMErrorType) bool {
	switch errType {
	case TPMErrorPCRMismatch, TPMErrorLockout, TPMErrorInvalidParam, TPMErrorUnavailable:
		return false
	case TPMErrorWrongPIN, TPMErrorCommunication, TPMErrorHandleInvalid, TPMErrorBadAuth, TPMErrorUnknown:
		return true
	default:
		return true
	}
}

// TokenUnlockError wraps TPM unlock failures with classification
type TokenUnlockError struct {
	Type    TPMErrorType
	Message string
	Err     error
}

func (e *TokenUnlockError) Error() string {
	return fmt.Sprintf("token unlock failed: %s", e.Message)
}

func (e *TokenUnlockError) Unwrap() error {
	return e.Err
}

// findCryptsetup finds the cryptsetup binary
func findCryptsetup() string {
	if cryptsetupBin != "" {
		return cryptsetupBin
	}
	for _, path := range cryptsetupPaths {
		if _, err := os.Stat(path); err == nil {
			Debug("cryptsetup: found binary at %s\n", path)
			cryptsetupBin = path
			return path
		}
	}
	Debug("cryptsetup: binary not found in any path\n")
	return ""
}

// UnlockDevices discovers and unlocks all LUKS devices
// Returns true if at least one device was unlocked, false if none found
func UnlockDevices() (bool, error) {
	cs := findCryptsetup()
	if cs == "" {
		return false, nil
	}

	// Wait a moment for block devices to settle
	time.Sleep(500 * time.Millisecond)

	devices, err := discoverLUKSDevices(cs)
	if err != nil {
		return false, fmt.Errorf("failed to discover LUKS devices: %w", err)
	}

	if len(devices) == 0 {
		return false, nil
	}

	for _, dev := range devices {
		Debug("cryptsetup: unlocking %s\n", dev.Path)
		if err := unlockDevice(cs, dev); err != nil {
			return false, fmt.Errorf("failed to unlock %s: %w", dev.Path, err)
		}
	}

	return true, nil
}

// LUKSDevice represents a LUKS encrypted device
type LUKSDevice struct {
	Path string
	Name string // Mapped name (from crypttab or auto-generated)
	UUID string
}

// discoverLUKSDevices finds all LUKS devices in the system
func discoverLUKSDevices(cs string) ([]LUKSDevice, error) {
	var devices []LUKSDevice
	seen := make(map[string]bool)
	var candidates []string

	// Dynamically discover block devices from /sys/block
	sysBlocks, err := os.ReadDir("/sys/block")
	if err != nil {
		Debug("cryptsetup: failed to read /sys/block: %v\n", err)
	} else {
		for _, block := range sysBlocks {
			name := block.Name()
			// Skip ram, loop (without number), and dm devices
			if strings.HasPrefix(name, "ram") || name == "loop" || strings.HasPrefix(name, "dm-") {
				continue
			}

			// Add the block device itself
			devPath := filepath.Join("/dev", name)
			if _, err := os.Stat(devPath); err == nil {
				candidates = append(candidates, devPath)
			}

			// Scan for partitions in /sys/block/<device>/
			partitions, _ := filepath.Glob(filepath.Join("/sys/block", name, name+"*"))
			for _, part := range partitions {
				partName := filepath.Base(part)
				partDev := filepath.Join("/dev", partName)
				if _, err := os.Stat(partDev); err == nil {
					candidates = append(candidates, partDev)
				}
			}
		}
	}

	Debug("cryptsetup: scanning %d block devices\n", len(candidates))
	for _, c := range candidates {
		Debug("cryptsetup: candidate: %s\n", c)
	}

	// Check each candidate
	for _, path := range candidates {
		if seen[path] {
			continue
		}
		seen[path] = true

		Debug("cryptsetup: checking %s for LUKS\n", path)
		if isLUKS(cs, path) {
			Debug("cryptsetup: found LUKS device: %s\n", path)
			dev := LUKSDevice{
				Path: path,
				Name: generateMappedName(path),
			}
			if uuid, err := getLUKSUUID(cs, path); err == nil {
				dev.UUID = uuid
			}
			devices = append(devices, dev)
		}
	}

	return devices, nil
}

// isLUKS checks if a device is a LUKS container
func isLUKS(cs, path string) bool {
	// First, try to read the LUKS magic header directly
	f, err := os.Open(path)
	if err != nil {
		Debug("cryptsetup: cannot open %s: %v\n", path, err)
		return false
	}
	magic := make([]byte, 6)
	n, err := f.Read(magic)
	f.Close()
	if err != nil || n < 6 {
		Debug("cryptsetup: cannot read %s: %v\n", path, err)
		return false
	}
	// LUKS magic is "LUKS\xba\xbe" at offset 0
	if string(magic[:4]) == "LUKS" {
		Debug("cryptsetup: %s has LUKS magic header\n", path)
	} else {
		Debug("cryptsetup: %s magic: %x (not LUKS)\n", path, magic)
		return false
	}

	cmd := exec.Command(cs, "isLuks", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		Debug("cryptsetup: isLuks %s failed: %v, output: %s\n", path, err, strings.TrimSpace(string(output)))
		return false
	}
	Debug("cryptsetup: isLuks %s succeeded\n", path)
	return true
}

// getLUKSUUID gets the UUID of a LUKS device
func getLUKSUUID(cs, path string) (string, error) {
	out, err := exec.Command(cs, "luksUUID", path).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// generateMappedName creates a dm name for the device
func generateMappedName(path string) string {
	base := filepath.Base(path)
	return "luks-" + base
}

// unlockDevice attempts to unlock a LUKS device
func unlockDevice(cs string, dev LUKSDevice) error {
	// Check if already unlocked
	mappedPath := "/dev/mapper/" + dev.Name
	if _, err := os.Stat(mappedPath); err == nil {
		Debug("cryptsetup: %s already unlocked\n", dev.Path)
		return nil
	}

	// Check if device has any tokens (TPM2, FIDO2, etc.)
	if hasTokens(cs, dev.Path) {
		console.DebugPrint("cryptsetup: found token(s) on %s, trying token unlock\n", dev.Path)
		err := unlockWithToken(cs, dev)

		if err == nil {
			console.DebugPrint("cryptsetup: %s unlocked with token\n", dev.Path)
			LogFunc("LUKS_UNLOCK", "device", dev.Path, "method", "token", "status", "ok")
			return nil
		}

		console.DebugPrint("cryptsetup: token unlock failed: %v\n", err)

		// Strict mode: no passphrase fallback
		if StrictMode {
			console.Print("cryptsetup: strict mode - no passphrase fallback\n")
			LogFunc("LUKS_FAIL", "device", dev.Path, "method", "token", "error", err.Error(), "mode", "strict")
			return fmt.Errorf("token unlock failed (strict mode): %w", err)
		}

		// Normal mode: fall back to passphrase
		console.Print("cryptsetup: falling back to passphrase: %v\n", err)

		// Show failure reason in TUI with appropriate message for error type
		if tui.IsEnabled() {
			var msg string
			if tokenErr, ok := err.(*TokenUnlockError); ok {
				switch tokenErr.Type {
				case TPMErrorLockout:
					msg = "TPM locked - use recovery passphrase"
				case TPMErrorPCRMismatch:
					msg = "TPM policy mismatch - use recovery passphrase"
				case TPMErrorInvalidParam:
					msg = "TPM configuration error - use recovery passphrase"
				case TPMErrorCommunication:
					msg = "TPM communication error - use recovery passphrase"
				case TPMErrorHandleInvalid:
					msg = "TPM session error - use recovery passphrase"
				case TPMErrorBadAuth:
					msg = "TPM authorization failed - use recovery passphrase"
				default:
					msg = fmt.Sprintf("TPM unlock failed: %v", err)
				}
			} else {
				msg = fmt.Sprintf("TPM unlock failed: %v", err)
			}
			tui.PasswordError(msg)
		}

		LogFunc("PASSPHRASE_FALLBACK", "device", dev.Path, "reason", err.Error())
	}

	// Use passphrase (only reached if tokens not present or in non-strict mode)
	if err := unlockWithPassphrase(cs, dev); err != nil {
		LogFunc("LUKS_FAIL", "device", dev.Path, "method", "passphrase", "error", err.Error())
		return err
	}
	LogFunc("LUKS_UNLOCK", "device", dev.Path, "method", "passphrase", "status", "ok")
	return nil
}

// hasTokens checks if a LUKS device has any tokens enrolled
func hasTokens(cs, path string) bool {
	cmd := exec.Command(cs, "luksDump", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	outStr := string(output)

	// Check for systemd-tpm2 token specifically
	if strings.Contains(outStr, "systemd-tpm2") {
		Debug("cryptsetup: found systemd-tpm2 token on %s\n", path)
		return true
	}

	// Check for any token section with actual tokens (not just "Tokens:" with nothing after)
	lines := strings.Split(outStr, "\n")
	inTokenSection := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Tokens:") {
			inTokenSection = true
			continue
		}
		if inTokenSection {
			// Token entries start with a number and colon, e.g., "  0: systemd-tpm2"
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' {
				Debug("cryptsetup: found token on %s: %s\n", path, trimmed)
				return true
			}
			// Empty line or new section ends token parsing
			if trimmed == "" || (len(trimmed) > 0 && !strings.HasPrefix(trimmed, " ")) {
				break
			}
		}
	}

	return false
}

// findTpm2Tool finds a tpm2-tools binary by name
func findTpm2Tool(name string) string {
	paths := []string{"/usr/bin/" + name, "/bin/" + name, "/usr/sbin/" + name}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// checkTPMLockoutStatus checks if the TPM is in DA lockout mode before prompting for PIN.
// Returns (locked bool, recoveryHint string)
func checkTPMLockoutStatus() (bool, string) {
	tpm2Getcap := findTpm2Tool("tpm2_getcap")
	if tpm2Getcap == "" {
		Debug("cryptsetup: tpm2_getcap not found, skipping lockout check\n")
		return false, "" // Can't check, assume not locked
	}

	cmd := exec.Command(tpm2Getcap, "properties-variable")
	cmd.Env = append(os.Environ(),
		"TPM2TOOLS_TCTI=device:/dev/tpmrm0",
		"TCTI=device:/dev/tpmrm0",
	)

	// Suppress stderr to avoid TUI corruption
	restoreStderr := console.SuppressStderr()
	output, err := cmd.CombinedOutput()
	restoreStderr()

	if err != nil {
		Debug("cryptsetup: tpm2_getcap failed: %v\n", err)
		return false, ""
	}

	// Parse output for lockout status
	outStr := string(output)

	// Helper to parse hex or decimal values
	parseValue := func(pattern *regexp.Regexp) int64 {
		if m := pattern.FindStringSubmatch(outStr); len(m) > 1 {
			val := strings.TrimPrefix(m[1], "0x")
			val = strings.TrimPrefix(val, "0X")
			// Try hex first if it was prefixed, otherwise try decimal
			if strings.ContainsAny(m[1], "xX") || strings.ContainsAny(val, "abcdefABCDEF") {
				if n, err := strconv.ParseInt(val, 16, 64); err == nil {
					return n
				}
			}
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				return n
			}
		}
		return 0
	}

	// Check inLockout flag directly (most reliable)
	inLockoutPattern := regexp.MustCompile(`inLockout:\s*(\d+)`)
	if m := inLockoutPattern.FindStringSubmatch(outStr); len(m) > 1 && m[1] == "1" {
		Debug("cryptsetup: TPM inLockout flag is set\n")
		// Get recovery time
		recoveryPattern := regexp.MustCompile(`TPM2_PT_LOCKOUT_RECOVERY:\s*(0x[0-9a-fA-F]+|\d+)`)
		lockoutRecovery := parseValue(recoveryPattern)
		hint := ""
		if lockoutRecovery > 0 {
			hint = fmt.Sprintf("Wait %d seconds or reboot to clear lockout", lockoutRecovery)
		} else {
			hint = "Reboot to clear lockout"
		}
		return true, hint
	}

	// Fallback: check counter vs max
	counterPattern := regexp.MustCompile(`TPM2_PT_LOCKOUT_COUNTER:\s*(0x[0-9a-fA-F]+|\d+)`)
	maxPattern := regexp.MustCompile(`TPM2_PT_MAX_AUTH_FAIL:\s*(0x[0-9a-fA-F]+|\d+)`)
	recoveryPattern := regexp.MustCompile(`TPM2_PT_LOCKOUT_RECOVERY:\s*(0x[0-9a-fA-F]+|\d+)`)

	lockoutCounter := parseValue(counterPattern)
	maxAuthFail := parseValue(maxPattern)
	lockoutRecovery := parseValue(recoveryPattern)

	Debug("cryptsetup: TPM lockout status - counter=%d, max=%d, recovery=%ds\n", lockoutCounter, maxAuthFail, lockoutRecovery)

	// Check if in lockout (counter >= max means locked)
	if maxAuthFail > 0 && lockoutCounter >= maxAuthFail {
		hint := ""
		if lockoutRecovery > 0 {
			hint = fmt.Sprintf("Wait %d seconds or reboot to clear lockout", lockoutRecovery)
		} else {
			hint = "Reboot to clear lockout"
		}
		return true, hint
	}

	return false, ""
}

// unlockWithToken attempts to unlock using any available token (TPM2, FIDO2, etc.)
func unlockWithToken(cs string, dev LUKSDevice) error {
	// Wait for TPM device to be ready
	if !waitForTPM() {
		return &TokenUnlockError{
			Type:    TPMErrorUnavailable,
			Message: "TPM device not available",
		}
	}

	// Pre-check for lockout BEFORE prompting for PIN
	if locked, hint := checkTPMLockoutStatus(); locked {
		msg := "TPM locked - too many failed attempts"
		if tui.IsEnabled() {
			tui.ShowTPMLockout(msg, hint)
		} else {
			console.Print("cryptsetup: %s\n", msg)
			if hint != "" {
				console.Print("cryptsetup: %s\n", hint)
			}
		}
		LogFunc("TPM_LOCKOUT", "device", dev.Path, "hint", hint)
		return &TokenUnlockError{Type: TPMErrorLockout, Message: msg}
	}

	// Check if TPM2 token requires PIN
	needsPIN := hasPINRequired(cs, dev.Path)
	if needsPIN {
		Debug("cryptsetup: TPM2 token requires PIN\n")
		return unlockWithTokenPIN(cs, dev)
	}

	return unlockWithTokenNoPIN(cs, dev)
}

// unlockWithTokenNoPIN attempts token unlock without PIN (single attempt)
func unlockWithTokenNoPIN(cs string, dev LUKSDevice) error {
	cmd := exec.Command(cs, "open", "--token-only", dev.Path, dev.Name)
	cmd.Env = append(os.Environ(),
		"TPM2TOOLS_TCTI=device:/dev/tpmrm0",
		"TCTI=device:/dev/tpmrm0",
	)
	cmd.Stdin = nil

	// Capture stdout/stderr - tpm2-tss outputs errors to stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // Capture stdout to prevent console leak
	cmd.Stderr = &stderr

	// Suppress stderr from tpm2-tss library when TUI is active
	restoreStderr := console.SuppressStderr()
	err := cmd.Run()
	restoreStderr()

	if err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		Debug("cryptsetup: token unlock stderr: %s\n", stderrStr)
		logPCRDebugInfo(cs, dev.Path)

		errType := classifyTPMError(stderrStr)
		return &TokenUnlockError{
			Type:    errType,
			Message: stderrStr,
			Err:     err,
		}
	}

	return ensureMapperNode(dev.Name)
}

// unlockWithTokenPIN attempts token unlock with PIN and retry logic
func unlockWithTokenPIN(cs string, dev LUKSDevice) error {
	var lastError error
	var pin string
	var err error

	for attempt := 1; attempt <= maxPINAttempts; attempt++ {
		// Prompt for PIN (first attempt or after error with retry)
		if attempt == 1 {
			// First attempt - use PromptPassword to set up initial prompt
			if tui.IsEnabled() {
				pin, err = tui.PromptPassword(dev.Path + " (TPM PIN)")
			} else {
				pin, err = console.ReadPassword(fmt.Sprintf("Enter TPM2 PIN for %s: ", dev.Path))
			}
		}
		// For subsequent attempts, pin is already set by PasswordErrorWithRetry below

		if err != nil {
			if tui.IsEnabled() {
				tui.PasswordPromptDone()
			}
			return fmt.Errorf("failed to read PIN: %w", err)
		}

		// Attempt unlock with stdout/stderr capture (prevent any output leak)
		cmd := exec.Command(cs, "open", "--token-only", dev.Path, dev.Name)
		cmd.Env = append(os.Environ(),
			"TPM2TOOLS_TCTI=device:/dev/tpmrm0",
			"TCTI=device:/dev/tpmrm0",
		)
		cmd.Stdin = strings.NewReader(pin + "\n")

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout // Capture stdout to prevent console leak
		cmd.Stderr = &stderr

		// Suppress stderr from tpm2-tss library when TUI is active
		restoreStderr := console.SuppressStderr()
		cmdErr := cmd.Run()
		restoreStderr()

		if cmdErr == nil {
			// Success - signal password prompt complete
			if tui.IsEnabled() {
				tui.PasswordPromptDone()
			}
			return ensureMapperNode(dev.Name)
		}

		// Classify error from tpm2-tss stderr
		stderrStr := strings.TrimSpace(stderr.String())
		Debug("cryptsetup: token unlock attempt %d stderr: %s\n", attempt, stderrStr)

		errType := classifyTPMError(stderrStr)

		// Map error type to user-friendly message (never show raw stderr to user)
		var userMsg string
		switch errType {
		case TPMErrorWrongPIN:
			userMsg = fmt.Sprintf("Incorrect PIN (attempt %d of %d)", attempt, maxPINAttempts)
		case TPMErrorPCRMismatch:
			userMsg = "TPM policy mismatch - system configuration changed"
		case TPMErrorInvalidParam:
			userMsg = "TPM policy configuration error"
		case TPMErrorLockout:
			userMsg = "TPM locked - too many failed attempts"
		case TPMErrorCommunication:
			userMsg = "TPM communication error - check device connection"
		case TPMErrorHandleInvalid:
			userMsg = "TPM session error - retrying may help"
		case TPMErrorBadAuth:
			userMsg = fmt.Sprintf("TPM authorization failed (attempt %d of %d)", attempt, maxPINAttempts)
		default:
			userMsg = "TPM unlock failed"
		}

		lastError = &TokenUnlockError{Type: errType, Message: userMsg, Err: cmdErr}

		// Retry for retryable errors (wrong PIN or unknown) if not last attempt
		if isRetryableTPMError(errType) && attempt < maxPINAttempts {
			LogFunc("TPM_PIN_FAIL", "device", dev.Path, "attempt", strconv.Itoa(attempt))
			// Show error and wait for next PIN attempt
			if tui.IsEnabled() {
				pin, err = tui.PasswordErrorWithRetry(userMsg)
			} else {
				console.Print("cryptsetup: %s\n", userMsg)
				pin, err = console.ReadPassword(fmt.Sprintf("Enter TPM2 PIN for %s: ", dev.Path))
			}
			continue
		}

		// Non-retryable error or last attempt - show appropriate error
		if tui.IsEnabled() {
			switch errType {
			case TPMErrorLockout:
				// Check for recovery hint
				_, hint := checkTPMLockoutStatus()
				tui.ShowTPMLockout(userMsg, hint)
			case TPMErrorPCRMismatch, TPMErrorInvalidParam:
				tui.ShowTPMError(userMsg)
				tui.PasswordPromptDone()
			default:
				tui.PasswordError(userMsg)
				tui.PasswordPromptDone()
			}
		} else {
			console.Print("cryptsetup: %s\n", userMsg)
		}

		if errType != TPMErrorWrongPIN {
			logPCRDebugInfo(cs, dev.Path)
			LogFunc("TPM_ERROR", "device", dev.Path, "type", fmt.Sprintf("%d", errType), "message", userMsg)
		} else {
			LogFunc("TPM_PIN_EXHAUSTED", "device", dev.Path)
		}
		return lastError
	}

	return fmt.Errorf("failed to unlock after %d PIN attempts: %w", maxPINAttempts, lastError)
}

// logPCRDebugInfo logs the enrolled PCRs and their current values for debugging
func logPCRDebugInfo(cs, path string) {
	// Get enrolled PCRs from the LUKS token
	enrolledPCRs, bank, err := getEnrolledPCRs(cs, path)
	if err != nil {
		Debug("cryptsetup: failed to get enrolled PCRs: %v\n", err)
		return
	}

	if len(enrolledPCRs) == 0 {
		Debug("cryptsetup: no PCRs enrolled in token\n")
		return
	}

	console.DebugPrint("cryptsetup: TPM2 unlock failed - enrolled PCRs: %v (bank: %s)\n", enrolledPCRs, bank)
	LogFunc("TPM_PCR_MISMATCH", "enrolled_pcrs", formatPCRList(enrolledPCRs), "bank", bank)

	// Read current PCR values
	pcrValues, err := readPCRValues(enrolledPCRs, bank)
	if err != nil {
		Debug("cryptsetup: failed to read PCR values: %v\n", err)
		console.DebugPrint("cryptsetup: could not read PCR values: %v\n", err)
		return
	}

	console.DebugPrint("cryptsetup: current PCR values:\n")
	for pcr, value := range pcrValues {
		console.DebugPrint("  PCR %d: %s\n", pcr, value)
		LogFunc("TPM_PCR_VALUE", "pcr", strconv.Itoa(pcr), "value", value)
	}
}

// getEnrolledPCRs extracts the PCR list and bank from LUKS token
func getEnrolledPCRs(cs, path string) ([]int, string, error) {
	// Export token data as JSON
	cmd := exec.Command(cs, "token", "export", path, "--token-id", "0")
	output, err := cmd.Output()
	if err != nil {
		// Try parsing luksDump output as fallback
		return getEnrolledPCRsFromLuksDump(cs, path)
	}

	// Parse JSON to find tpm2-pcrs and tpm2-pcr-bank
	var tokenData map[string]interface{}
	if err := json.Unmarshal(output, &tokenData); err != nil {
		return getEnrolledPCRsFromLuksDump(cs, path)
	}

	var pcrs []int
	bank := "sha256" // Default

	// Get PCR bank
	if bankVal, ok := tokenData["tpm2-pcr-bank"].(string); ok {
		bank = bankVal
	}

	// Get PCRs - can be an array of numbers
	if pcrVal, ok := tokenData["tpm2-pcrs"].([]interface{}); ok {
		for _, p := range pcrVal {
			if num, ok := p.(float64); ok {
				pcrs = append(pcrs, int(num))
			}
		}
	}

	return pcrs, bank, nil
}

// getEnrolledPCRsFromLuksDump parses luksDump output to find enrolled PCRs
func getEnrolledPCRsFromLuksDump(cs, path string) ([]int, string, error) {
	cmd := exec.Command(cs, "luksDump", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, "", err
	}

	var pcrs []int
	bank := "sha256"
	outStr := string(output)

	// Look for lines like "tpm2-pcrs: 7 11 14" or "tpm2-pcrs: [7, 11, 14]"
	pcrPattern := regexp.MustCompile(`tpm2-pcrs:\s*\[?([0-9,\s]+)\]?`)
	if matches := pcrPattern.FindStringSubmatch(outStr); len(matches) > 1 {
		pcrStr := matches[1]
		// Parse comma or space separated numbers
		for _, part := range regexp.MustCompile(`[,\s]+`).Split(pcrStr, -1) {
			part = strings.TrimSpace(part)
			if num, err := strconv.Atoi(part); err == nil {
				pcrs = append(pcrs, num)
			}
		}
	}

	// Look for tpm2-pcr-bank
	bankPattern := regexp.MustCompile(`tpm2-pcr-bank:\s*(\S+)`)
	if matches := bankPattern.FindStringSubmatch(outStr); len(matches) > 1 {
		bank = matches[1]
	}

	return pcrs, bank, nil
}

// readPCRValues reads the current values of the specified PCRs using tpm2_pcrread
func readPCRValues(pcrs []int, bank string) (map[int]string, error) {
	// Find tpm2_pcrread binary
	tpm2PcrreadPaths := []string{"/usr/bin/tpm2_pcrread", "/bin/tpm2_pcrread"}
	var tpm2Pcrread string
	for _, p := range tpm2PcrreadPaths {
		if _, err := os.Stat(p); err == nil {
			tpm2Pcrread = p
			break
		}
	}

	if tpm2Pcrread == "" {
		return nil, fmt.Errorf("tpm2_pcrread not found")
	}

	// Build PCR selection string, e.g., "sha256:7,11,14"
	var pcrNums []string
	for _, pcr := range pcrs {
		pcrNums = append(pcrNums, strconv.Itoa(pcr))
	}
	pcrSelection := fmt.Sprintf("%s:%s", bank, strings.Join(pcrNums, ","))

	cmd := exec.Command(tpm2Pcrread, pcrSelection)
	cmd.Env = append(os.Environ(),
		"TPM2TOOLS_TCTI=device:/dev/tpmrm0",
		"TCTI=device:/dev/tpmrm0",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tpm2_pcrread failed: %v, output: %s", err, string(output))
	}

	// Parse output like:
	//   sha256:
	//     7 : 0xABC123...
	//    11 : 0xDEF456...
	result := make(map[int]string)
	lines := strings.Split(string(output), "\n")
	pcrValuePattern := regexp.MustCompile(`^\s*(\d+)\s*:\s*(0x[0-9A-Fa-f]+)`)

	for _, line := range lines {
		if matches := pcrValuePattern.FindStringSubmatch(line); len(matches) > 2 {
			pcrNum, _ := strconv.Atoi(matches[1])
			result[pcrNum] = matches[2]
		}
	}

	return result, nil
}

// formatPCRList formats a list of PCRs for logging
func formatPCRList(pcrs []int) string {
	var parts []string
	for _, pcr := range pcrs {
		parts = append(parts, strconv.Itoa(pcr))
	}
	return strings.Join(parts, ",")
}

// hasPINRequired checks if TPM2 token requires PIN by parsing luksDump output
func hasPINRequired(cs, path string) bool {
	cmd := exec.Command(cs, "luksDump", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		Debug("cryptsetup: luksDump failed: %v\n", err)
		return false
	}
	outStr := string(output)

	// Look for "tpm2-pin: true" in the systemd-tpm2 token section
	// Use regex to handle variable whitespace (e.g. "tpm2-pin:         true")
	pinRegex := regexp.MustCompile(`tpm2-pin:\s+true`)
	hasPin := pinRegex.MatchString(outStr)

	Debug("cryptsetup: PIN detection for %s: %v\n", path, hasPin)
	if !hasPin && strings.Contains(outStr, "systemd-tpm2") {
		// Log detailed output if we expected a PIN but found none
		Debug("cryptsetup: systemd-tpm2 token found but no PIN detected (regex: %s). luksDump: %s\n", pinRegex.String(), outStr)
	}

	return hasPin
}

// ensureMapperNode ensures the /dev/mapper/<name> device node exists after unlock
func ensureMapperNode(name string) error {
	mappedPath := "/dev/mapper/" + name

	// Wait for node to appear (3 seconds for slow systems)
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(mappedPath); err == nil {
			Debug("cryptsetup: device node %s ready\n", mappedPath)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Try dmsetup mknodes as fallback
	Debug("cryptsetup: device node %s not found, trying dmsetup mknodes\n", mappedPath)
	dmsetupPaths := []string{"/usr/sbin/dmsetup", "/sbin/dmsetup"}
	for _, dmPath := range dmsetupPaths {
		if _, err := os.Stat(dmPath); err == nil {
			if err := exec.Command(dmPath, "mknodes").Run(); err != nil {
				Debug("cryptsetup: dmsetup mknodes failed: %v\n", err)
			}
			break
		}
	}

	// Final check
	if _, err := os.Stat(mappedPath); err == nil {
		Debug("cryptsetup: device node %s created via dmsetup\n", mappedPath)
		return nil
	}
	return fmt.Errorf("device node %s not created", mappedPath)
}

// waitForTPM waits for the TPM device to become available
func waitForTPM() bool {
	tpmDevices := []string{"/dev/tpmrm0", "/dev/tpm0"}

	Debug("cryptsetup: waiting for TPM device...\n")

	// Wait up to 3 seconds for TPM device
	for i := 0; i < 30; i++ {
		for _, dev := range tpmDevices {
			if _, err := os.Stat(dev); err == nil {
				Debug("cryptsetup: found TPM device: %s\n", dev)
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	Debug("cryptsetup: TPM device not found\n")
	LogFunc("TPM_UNAVAILABLE")
	return false
}

// unlockWithPassphrase prompts for a passphrase and unlocks the device
func unlockWithPassphrase(cs string, dev LUKSDevice) error {
	for attempts := 0; attempts < 3; attempts++ {
		var passphrase string
		var err error

		// Use TUI for password prompt when available, otherwise fall back to console
		if tui.IsEnabled() {
			passphrase, err = tui.PromptPassword(dev.Path)
		} else {
			passphrase, err = console.ReadPassword(fmt.Sprintf("Enter passphrase for %s: ", dev.Path))
		}
		if err != nil {
			return err
		}

		cmd := exec.Command(cs, "open", dev.Path, dev.Name)
		cmd.Stdin = strings.NewReader(passphrase + "\n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err == nil {
			// Ensure device node exists after unlock
			return ensureMapperNode(dev.Name)
		}

		errMsg := strings.TrimSpace(stderr.String())
		if tui.IsEnabled() {
			if errMsg != "" {
				tui.PasswordError(fmt.Sprintf("cryptsetup: %s", errMsg))
			} else {
				tui.PasswordError("Incorrect passphrase, try again")
			}
		} else {
			if errMsg != "" {
				console.Print("cryptsetup: %s\n", errMsg)
			}
			console.Print("cryptsetup: incorrect passphrase, try again\n")
		}
	}

	return fmt.Errorf("failed to unlock after 3 attempts")
}
