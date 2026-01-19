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
	"github.com/zaolin/vanguard/init/luks"
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

	// Measure LUKS header into PCR 8 before unlock
	// This ensures the policy can verify the LUKS header integrity
	if err := luks.MeasureHeader(dev.Path); err != nil {
		console.Print("cryptsetup: warning: failed to measure LUKS header for %s: %v\n", dev.Path, err)
		// We don't block unlock here - if policy requires PCR 8, TPM unlock will fail naturally
	}

	// Check if device has any tokens (TPM2, FIDO2, etc.)
	if hasTokens(cs, dev.Path) {
		console.DebugPrint("cryptsetup: found token(s) on %s, trying token unlock\n", dev.Path)
		if err := unlockWithToken(cs, dev); err == nil {
			console.DebugPrint("cryptsetup: %s unlocked with token\n", dev.Path)
			LogFunc("LUKS_UNLOCK", "device", dev.Path, "method", "tpm2", "status", "ok")
			return nil
		} else {
			console.DebugPrint("cryptsetup: token unlock failed: %v\n", err)
			console.Print("cryptsetup: falling back to passphrase\n")
			LogFunc("PASSPHRASE_FALLBACK", "device", dev.Path, "reason", err.Error())
		}
	}

	// Use passphrase
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

// unlockWithToken attempts to unlock using any available token (TPM2, FIDO2, etc.)
func unlockWithToken(cs string, dev LUKSDevice) error {
	// Wait for TPM device to be ready
	if !waitForTPM() {
		return fmt.Errorf("TPM device not available")
	}

	// Check if TPM2 token requires PIN
	needsPIN := hasPINRequired(cs, dev.Path)
	if needsPIN {
		Debug("cryptsetup: TPM2 token requires PIN\n")
	}

	// Use --token-only to prevent passphrase fallback
	cmd := exec.Command(cs, "open", "--token-only", dev.Path, dev.Name)

	// Set environment to help TPM2 libraries find the device
	cmd.Env = append(os.Environ(),
		"TPM2TOOLS_TCTI=device:/dev/tpmrm0",
		"TCTI=device:/dev/tpmrm0",
	)

	if needsPIN {
		// Prompt for PIN using TUI if available, otherwise console
		var pin string
		var err error
		if tui.IsEnabled() {
			pin, err = tui.PromptPassword(dev.Path + " (TPM PIN)")
		} else {
			pin, err = console.ReadPassword(fmt.Sprintf("Enter TPM2 PIN for %s: ", dev.Path))
		}
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
		cmd.Stdin = strings.NewReader(pin + "\n")
	} else {
		// Close stdin to prevent "Nothing to read on input" error
		cmd.Stdin = nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(output))
		if outStr != "" {
			Debug("cryptsetup: token unlock output: %s\n", outStr)
		}

		// Log PCR debug information when TPM unlock fails
		logPCRDebugInfo(cs, dev.Path)

		return fmt.Errorf("token unlock failed: %v", err)
	}

	// Ensure device node exists after unlock
	return ensureMapperNode(dev.Name)
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
		return false
	}

	// Look for "tpm2-pin" in the systemd-tpm2 token section
	// The output contains "tpm2-pin: true" when PIN is required
	return strings.Contains(string(output), "tpm2-pin")
}

// ensureMapperNode ensures the /dev/mapper/<name> device node exists after unlock
func ensureMapperNode(name string) error {
	mappedPath := "/dev/mapper/" + name

	// Wait briefly for node to appear
	for i := 0; i < 10; i++ {
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
			exec.Command(dmPath, "mknodes").Run()
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
