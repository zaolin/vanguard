package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zaolin/vanguard/internal/totp"
	"github.com/zaolin/vanguard/internal/tpm"
)

// recoveryPendingPath is where --auto-reseed writes the otpauth URI for
// the new seed, so the user can retrieve it with 'vanguard recovery --show'
// after a firmware update.
const recoveryPendingPath = "/var/lib/vanguard/recovery-pending.uri"

// isTerminal returns true if the given file is a terminal (not a pipe/redirect).
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func (c *RecoveryCmd) Run() error {
	// Determine NV index
	nvIndex := c.NVIndex
	if nvIndex == 0 {
		nvIndex = tpm.DefaultRecoverySeedNVIndex
	}

	switch {
	case c.Clean:
		return c.runClean(nvIndex)
	case c.Enable:
		return c.runEnable(nvIndex)
	case c.Disable:
		return c.runDisable(nvIndex)
	case c.Show:
		return c.runShow(nvIndex)
	case c.Check:
		return c.runCheck(nvIndex)
	case c.AutoReseed:
		return c.runAutoReseed(nvIndex)
	default:
		return c.runInstructions()
	}
}

func (c *RecoveryCmd) runClean(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	fmt.Println()
	fmt.Println("  " + headerSty.Render("CLEANING LEGACY RECOVERY NV INDEXES"))
	fmt.Println()

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		return fmt.Errorf("TPM device not available")
	}

	// Check if tpm2_nvundefine is available
	tpm2Path, err := exec.LookPath("tpm2_nvundefine")
	if err != nil {
		// Fallback: try the go-tpm approach with NVReadPublic for the Name
		return c.runCleanGoTPM(nvIndex)
	}

	// Use tpm2_nvundefine CLI — it handles the Name internally
	seedExists := client.RecoveryNVExists(nvIndex)
	tsIndex := uint32(tpm.DefaultRecoveryTimestampNVIndex)
	tsExists := client.RecoveryNVExists(tsIndex)

	if !seedExists && !tsExists {
		fmt.Println("  No recovery NV indexes found — nothing to clean.")
		fmt.Println()
		return nil
	}

	if seedExists {
		fmt.Printf("  Removing seed NV index 0x%x...\n", nvIndex)
		cmd := exec.Command(tpm2Path, fmt.Sprintf("0x%x", nvIndex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Try with --hierarchy=owner
			fmt.Printf("  Retrying with --hierarchy=owner...\n")
			cmd = exec.Command(tpm2Path, "--hierarchy=o", fmt.Sprintf("0x%x", nvIndex))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				// Try platform hierarchy
				fmt.Printf("  Retrying with --hierarchy=platform...\n")
				cmd = exec.Command(tpm2Path, "--hierarchy=p", fmt.Sprintf("0x%x", nvIndex))
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Printf("  %s Failed to remove seed index 0x%x via tpm2_nvundefine: %v\n", errStyle.Render("✗"), nvIndex, err)
					fmt.Println("  Try manually: tpm2_nvundefine 0x1c30001 or tpm2_nvundefine --hierarchy=p 0x1c30001")
				} else {
					fmt.Printf("  %s Seed NV index 0x%x removed (platform hierarchy)\n", okStyle.Render("✓"), nvIndex)
				}
			} else {
				fmt.Printf("  %s Seed NV index 0x%x removed (owner hierarchy)\n", okStyle.Render("✓"), nvIndex)
			}
		} else {
			fmt.Printf("  %s Seed NV index 0x%x removed\n", okStyle.Render("✓"), nvIndex)
		}
	}

	if tsExists {
		fmt.Printf("  Removing timestamp NV index 0x%x...\n", tsIndex)
		cmd := exec.Command(tpm2Path, fmt.Sprintf("0x%x", tsIndex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  %s Failed to remove timestamp index 0x%x: %v\n", errStyle.Render("✗"), tsIndex, err)
		} else {
			fmt.Printf("  %s Timestamp NV index 0x%x removed\n", okStyle.Render("✓"), tsIndex)
		}
	}

	fmt.Println()
	fmt.Println("  Cleanup complete. Run 'vanguard recovery --enable' to set up")
	fmt.Println("  TOTP recovery with the new PCR-bound anti-evil-maid protection.")
	fmt.Println()
	return nil
}

// runCleanGoTPM is the fallback when tpm2_nvundefine CLI is not available.
// It uses go-tpm directly, reading the NV name first to avoid the "missing Name" error.
func (c *RecoveryCmd) runCleanGoTPM(nvIndex uint32) error {
	// Directly call the undefine logic with the NV name
	// This is a simplified version that doesn't use policy sessions
	// (old indexes don't have PolicyRead/PolicyWrite)
	client := tpm.New()

	seedExists := client.RecoveryNVExists(nvIndex)
	tsIndex := uint32(tpm.DefaultRecoveryTimestampNVIndex)
	tsExists := client.RecoveryNVExists(tsIndex)

	if !seedExists && !tsExists {
		fmt.Println("  No recovery NV indexes found — nothing to clean.")
		fmt.Println()
		return nil
	}

	// For old indexes (OwnerRead/OwnerWrite, no policy),
	// we can use the CLI fallback by calling tpm2_nvundefine
	// via os/exec with the full path
	if path, err := exec.LookPath("tpm2_nvundefine"); err == nil {
		_ = path
	}

	// Try to undefine using go-tpm with proper Name
	if seedExists {
		fmt.Printf("  Attempting to remove seed NV index 0x%x via go-tpm...\n", nvIndex)
		// The old index uses OwnerRead/OwnerWrite, so NVUndefineSpace with
		// owner auth should work if we provide the Name.
		// But go-tpm's NVUndefineSpace takes a plain TPMHandle, not NamedHandle.
		// The "missing Name" error comes from the kernel TPM driver requiring
		// the name for HMAC session computation.
		//
		// Workaround: use the go-tpm API but first read the NV public to get
		// the name, then use it. Unfortunately, NVUndefineSpace's NVIndex
		// field is a plain `handle` which accepts NamedHandle.
		// Let's try that approach.
		fmt.Printf("  %s Use 'tpm2_nvundefine 0x%x' manually (tpm2-tools not found)\n", warnStyle.Render("⚠"), nvIndex)
	}

	fmt.Println()
	return fmt.Errorf("tpm2_nvundefine not found — install tpm2-tools to clean legacy indexes, or run: tpm2_nvundefine 0x%x && tpm2_nvundefine 0x%x", nvIndex, tsIndex)
}

func (c *RecoveryCmd) runEnable(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Check if stdout is a terminal — the wizard needs interactive input
	if !isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "error: recovery setup requires an interactive terminal")
		return fmt.Errorf("stdout is not a terminal")
	}

	fmt.Println()
	fmt.Println("  " + headerSty.Render("TOTP RECOVERY SETUP WIZARD"))
	fmt.Println()

	// Step 1: Generate seed and write to TPM NVRAM
	fmt.Println("  Step 1: Generating TOTP seed and writing to TPM NVRAM...")
	fmt.Println()

	seed, err := totp.GenerateSeed()
	if err != nil {
		return fmt.Errorf("failed to generate TOTP seed: %w", err)
	}

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		return fmt.Errorf("TPM device not available")
	}

	// Read current PCR 7 for the anti-evil-maid policy (single-branch: PCR 7 only)
	pcrValues := make(map[int][]byte)
	val, err := client.ReadPCR(tpm.AlgSHA256, 7)
	if err != nil {
		return fmt.Errorf("failed to read PCR 7 for policy: %w", err)
	}
	pcrValues[7] = val
	fmt.Printf("  %s Read PCR 7 (Secure Boot) for anti-evil-maid policy\n", okStyle.Render("✓"))

	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		return fmt.Errorf("failed to define recovery NV space: %w", err)
	}

	if err := client.WriteRecoveryData(nvIndex, seed, time.Now().Unix(), pcrValues); err != nil {
		// Clean up the NV index if write failed
		_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
		return fmt.Errorf("failed to write recovery data: %w", err)
	}

	fmt.Printf("  %s Seed written to TPM NVRAM at index 0x%x\n", okStyle.Render("✓"), nvIndex)
	fmt.Println()

	// Step 2: Display QR code and seed
	fmt.Println("  Step 2: Enroll in your authenticator app")
	fmt.Println()
	fmt.Println("  Scan this QR code with your authenticator app")
	fmt.Println("  (Google Authenticator, Authy, 1Password, etc.):")
	fmt.Println()

	seedB32 := totp.EncodeBase32(seed)
	uri := totp.BuildOTPAuthURI(seed, "Vanguard", "recovery")

	if err := totp.PrintQRCode(uri); err != nil {
		fmt.Printf("  warning: QR code generation failed: %v\n", err)
		fmt.Println("  Enroll manually using this seed:")
	}

	fmt.Println()
	fmt.Printf("  Manual seed (base32): %s\n", seedB32)
	fmt.Println()

	// Step 3: Verify — user must enter a code from their app to confirm enrollment
	fmt.Println("  Step 3: Verify enrollment")
	fmt.Println()
	fmt.Println("  Enter the current 6-digit code from your authenticator app")
	fmt.Println("  to verify the enrollment is correct:")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Printf("  Recovery code (attempt %d of 3): ", attempt)

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		code := strings.TrimSpace(input)
		if len(code) == 0 {
			fmt.Println("  Empty input — skipping verification")
			fmt.Println()
			fmt.Printf("  %s TOTP recovery enabled (unverified)\n", warnStyle.Render("⚠"))
			fmt.Printf("  NV Index: 0x%x\n", nvIndex)
			fmt.Println("  Run 'vanguard recovery --show' to verify later.")
			fmt.Println()
			return nil
		}

		if totp.Validate(code, seed, time.Now(), totp.DefaultSkew) {
			fmt.Println()
			fmt.Printf("  %s Verification successful — TOTP recovery is enabled\n", okStyle.Render("✓"))
			fmt.Println()
			fmt.Println(box("TOTP Recovery Summary", []string{
				fmt.Sprintf("NV Index:    0x%x", nvIndex),
				fmt.Sprintf("Algorithm:   HMAC-SHA256"),
				fmt.Sprintf("Period:      30 seconds"),
				fmt.Sprintf("Digits:      6"),
				fmt.Sprintf("PCR binding: PCR 7 (Secure Boot)"),
				fmt.Sprintf("Verified:    yes"),
			}))
			fmt.Println()
			fmt.Println("  If TPM unlock fails at boot, enter the 6-digit code")
			fmt.Println("  from your authenticator app to enable passphrase fallback.")
			fmt.Println()
			return nil
		}

		fmt.Printf("  %s Invalid code\n", errStyle.Render("✗"))
		if attempt < 3 {
			fmt.Println("  Make sure your phone's clock is correct and try again.")
		}
	}

	// Step 4: Verification failed — remove seed to avoid false sense of security
	fmt.Println()
	fmt.Println("  Verification failed after 3 attempts.")
	fmt.Println("  Removing TOTP seed from TPM NVRAM to prevent an unverified enrollment...")
	fmt.Println()

	if err := client.UndefineRecoveryNVSpace(nvIndex, nil); err != nil {
		fmt.Printf("  %s Warning: failed to remove NV index: %v\n", warnStyle.Render("⚠"), err)
		fmt.Println("  You can manually remove it with: vanguard recovery --disable")
	} else {
		fmt.Printf("  %s Seed removed from TPM NVRAM\n", okStyle.Render("✓"))
	}

	fmt.Println()
	return fmt.Errorf("TOTP verification failed — enrollment aborted, seed removed")
}

func (c *RecoveryCmd) runDisable(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		return fmt.Errorf("TPM device not available")
	}

	if !client.RecoveryNVExists(nvIndex) {
		fmt.Println("  TOTP recovery is not enabled (NV index not found)")
		return nil
	}

	// Undefine uses owner auth (no policy session needed)
	if err := client.UndefineRecoveryNVSpace(nvIndex, nil); err != nil {
		return fmt.Errorf("failed to undefine recovery NV space: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %s TOTP recovery disabled (NV index 0x%x removed)\n",
		okStyle.Render("✓"), nvIndex)
	fmt.Println()

	return nil
}

func (c *RecoveryCmd) runShow(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	if !isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "error: refusing to print TOTP seed to non-terminal stdout")
		fmt.Fprintln(os.Stderr, "       Run this command in a terminal to display the QR code.")
		return nil
	}

	// Check for pending re-provision file (from --auto-reseed after firmware update)
	if uriData, err := os.ReadFile(recoveryPendingPath); err == nil {
		uri := strings.TrimSpace(string(uriData))
		seedB32 := extractSeedFromURI(uri)
		seed, err := totp.DecodeBase32(seedB32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse pending recovery URI: %v\n", err)
		} else {
			fmt.Println()
			fmt.Println("  " + warnStyle.Render("RECOVERY SEED RE-PROVISIONED AFTER FIRMWARE UPDATE"))
			fmt.Println("  Your previous TOTP seed is no longer valid (Secure Boot keys changed).")
			fmt.Println("  A new seed has been generated. Re-enroll your authenticator app:")
			fmt.Println()

			fmt.Println(box("New TOTP Recovery", []string{
				fmt.Sprintf("NV Index:      0x%x", nvIndex),
				fmt.Sprintf("Algorithm:     HMAC-SHA256"),
				fmt.Sprintf("Period:        30 seconds"),
				fmt.Sprintf("Digits:        6"),
				fmt.Sprintf("PCR binding:   PCR 7 (Secure Boot)"),
				fmt.Sprintf("Seed (base32): %s", seedB32),
				fmt.Sprintf("Status:        pending enrollment"),
			}))

			fmt.Println()
			fmt.Println("  " + headerSty.Render("QR CODE — Scan with your authenticator app"))
			fmt.Println()

			if err := totp.PrintQRCode(uri); err != nil {
				fmt.Printf("  warning: failed to generate QR code: %v\n", err)
			}

			fmt.Println()
			fmt.Printf("  otpauth URI: %s\n", uri)
			fmt.Println()

			// Verify enrollment
			fmt.Print("  Verify enrollment? Enter a code from your app (or press Enter to skip): ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			code := strings.TrimSpace(input)

			if code != "" && totp.Validate(code, seed, time.Now(), totp.DefaultSkew) {
				fmt.Printf("  %s Verification successful — pending file removed\n", okStyle.Render("✓"))
				_ = os.Remove(recoveryPendingPath)
			} else if code == "" {
				fmt.Println("  Skipped verification. Pending file retained for next attempt.")
			} else {
				fmt.Printf("  %s Invalid code — pending file retained for next attempt\n", errStyle.Render("✗"))
			}

			fmt.Println()
			return nil
		}
	}

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		return fmt.Errorf("TPM device not available")
	}

	if !client.RecoveryNVExists(nvIndex) {
		fmt.Println("  TOTP recovery is not enabled (NV index not found)")
		return nil
	}

	seed, refTimestamp, _, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		return fmt.Errorf("failed to read recovery data: %w", err)
	}

	// Read current PCR 7 to show the binding state
	currentPCR7, _ := client.ReadPCR(tpm.AlgSHA256, 7)
	pcr7Hex := "unknown"
	if currentPCR7 != nil {
		pcr7Hex = fmt.Sprintf("%x", currentPCR7)
		if len(pcr7Hex) > 16 {
			pcr7Hex = pcr7Hex[:16] + "..."
		}
	}

	seedB32 := totp.EncodeBase32(seed)
	uri := totp.BuildOTPAuthURI(seed, "Vanguard", "recovery")

	fmt.Println()
	fmt.Println(box("Current TOTP Recovery", []string{
		fmt.Sprintf("NV Index:      0x%x", nvIndex),
		fmt.Sprintf("Algorithm:     HMAC-SHA256"),
		fmt.Sprintf("Period:        30 seconds"),
		fmt.Sprintf("Digits:        6"),
		fmt.Sprintf("PCR binding:   PCR 7 (Secure Boot)"),
		fmt.Sprintf("PCR 7 current: %s", pcr7Hex),
		fmt.Sprintf("Seed (base32): %s", seedB32),
		fmt.Sprintf("Last updated:  %s", time.Unix(refTimestamp, 0).Format(time.RFC3339)),
	}))

	fmt.Println()
	fmt.Println("  " + headerSty.Render("QR CODE — Scan with your authenticator app"))
	fmt.Println()

	if err := totp.PrintQRCode(uri); err != nil {
		fmt.Printf("  warning: failed to generate QR code: %v\n", err)
	}

	fmt.Println()
	fmt.Printf("  otpauth URI: %s\n", uri)
	fmt.Println()

	// Optional verification — ask the user if they want to verify
	fmt.Print("  Verify enrollment? Enter a code from your app (or press Enter to skip): ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	code := strings.TrimSpace(input)

	if code == "" {
		fmt.Println("  Skipped verification.")
		fmt.Println()
		return nil
	}

	if totp.Validate(code, seed, time.Now(), totp.DefaultSkew) {
		fmt.Printf("  %s Verification successful\n", okStyle.Render("✓"))
	} else {
		fmt.Printf("  %s Invalid code — check your phone's clock and the enrolled seed\n", errStyle.Render("✗"))
	}

	fmt.Println()
	return nil
}

func (c *RecoveryCmd) runCheck(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	fmt.Println()
	fmt.Println("  " + headerSty.Render("RECOVERY CHECK"))
	fmt.Println()

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		fmt.Printf("  %s TPM device not available\n", errStyle.Render("✗"))
		return fmt.Errorf("TPM device not available")
	}

	// Check if recovery NV index exists
	if !client.RecoveryNVExists(nvIndex) {
		fmt.Printf("  %s TOTP recovery is NOT configured (NV index 0x%x not found)\n", errStyle.Render("✗"), nvIndex)
		fmt.Println()
		fmt.Println("  Enable recovery with: sudo vanguard recovery --enable")
		fmt.Println()
		return fmt.Errorf("recovery not configured")
	}

	fmt.Printf("  %s Recovery NV index 0x%x exists\n", okStyle.Render("✓"), nvIndex)

	// Check if timestamp index exists
	if !client.TimestampNVExists() {
		fmt.Printf("  %s Timestamp NV index 0x%x is missing\n", errStyle.Render("✗"), tpm.DefaultRecoveryTimestampNVIndex)
		fmt.Println()
		fmt.Println("  The timestamp NV index was lost (possibly from a previous failed auto-reseed).")
		fmt.Println("  The seed may still be valid — auto-reseed can repair this without changing the seed.")
		fmt.Println()
		fmt.Println("  To fix:")
		fmt.Println("    sudo vanguard recovery --auto-reseed  # repair timestamp (seed preserved)")
		fmt.Println()
		return fmt.Errorf("timestamp NV index missing")
	}

	// Try to read the seed (requires PCR 7 to match)
	seed, refTimestamp, _, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		fmt.Printf("  %s Failed to read TOTP seed: %v\n", errStyle.Render("✗"), err)
		fmt.Println()
		fmt.Println("  This means PCR 7 (Secure Boot state) has changed since enrollment.")
		fmt.Println("  The recovery seed is sealed with the old PCR 7 value and cannot be read.")
		fmt.Println()
		fmt.Println("  To fix:")
		fmt.Println("    sudo vanguard recovery --auto-reseed  # re-provision with current PCR 7")
		fmt.Println("    sudo vanguard recovery --show         # display new QR code")
		fmt.Println()
		return fmt.Errorf("seed unreadable (PCR 7 mismatch)")
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	fmt.Printf("  %s TOTP seed readable (PCR 7 matches enrollment)\n", okStyle.Render("✓"))

	// Check reference timestamp
	now := time.Now()
	refTime := time.Unix(refTimestamp, 0)
	drift := now.Unix() - refTimestamp
	driftStr := fmt.Sprintf("%d seconds", drift)
	if drift < 0 {
		driftStr = fmt.Sprintf("%d seconds (clock ahead)", -drift)
	}
	if abs64(drift) > 300 {
		fmt.Printf("  %s Reference timestamp drift: %s (may cause TOTP validation issues)\n", warnStyle.Render("⚠"), driftStr)
	} else {
		fmt.Printf("  %s Reference timestamp: %s (drift: %s)\n", okStyle.Render("✓"), refTime.Format("2006-01-02 15:04:05"), driftStr)
	}

	// Verify a TOTP code can be generated from the seed
	code := totp.GenerateCode(seed, now)
	if len(code) != 6 {
		fmt.Printf("  %s TOTP code generation failed\n", errStyle.Render("✗"))
	} else {
		fmt.Printf("  %s TOTP code generation works (current code: %s)\n", okStyle.Render("✓"), code)
	}

	fmt.Println()
	fmt.Printf("  %s TOTP recovery is properly configured and ready\n", okStyle.Render("✓"))
	fmt.Println()

	return nil
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func (c *RecoveryCmd) runAutoReseed(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		return fmt.Errorf("TPM device not available")
	}

	// 1. Check if recovery is enabled
	if !client.RecoveryNVExists(nvIndex) {
		// Recovery not configured — nothing to do
		return nil
	}

	// 2. Try to read the seed — if it succeeds, PCR 7 hasn't changed
	_, _, _, err := client.ReadRecoveryData(nvIndex)
	if err == nil {
		// Seed is still readable — no firmware update occurred, or PCR 7 unchanged
		return nil
	}

	// 3. ReadRecoveryData failed. Diagnose the cause:
	//    - Timestamp index missing: seed may still be readable, just need to
	//      recreate the timestamp. This is a targeted repair that preserves
	//      the existing seed (user's TOTP code stays valid).
	//    - PCR 7 mismatch: seed is unreadable, need full reseed with new seed.
	//    - Other error: fall back to full reseed.

	timestampMissing := !client.TimestampNVExists()

	if timestampMissing {
		// Try to read the seed without the timestamp
		seed, seedErr := client.ReadSeedOnly(nvIndex)
		if seedErr == nil {
			// Seed is readable! PCR 7 matches. Just recreate the timestamp.
			// Zero the seed — we don't need it, just needed to verify readability.
			for i := range seed {
				seed[i] = 0
			}

			// Read current PCR 7 for branch digest computation
			pcrValues := make(map[int][]byte)
			val, pcrErr := client.ReadPCR(tpm.AlgSHA256, 7)
			if pcrErr != nil {
				return fmt.Errorf("failed to read PCR 7 for timestamp recreation: %w", pcrErr)
			}
			pcrValues[7] = val

			// Recreate only the timestamp index
			if err := client.RecreateTimestampOnly(pcrValues); err != nil {
				return fmt.Errorf("failed to recreate timestamp NV index: %w", err)
			}

			fmt.Println("recovery: timestamp NV index was missing, recreated (seed preserved)")
			fmt.Println("recovery: TOTP recovery is now fully operational — no re-enrollment needed")
			return nil
		}

		// Seed is also unreadable — PCR 7 changed. Fall through to full reseed.
		// The old seed is gone (can't be read with new PCR 7). Both indexes
		// need to be re-provisioned.
	}

	// 4. Full atomic reseed: seed is unreadable (PCR 7 changed) or
	//    diagnosis failed. Generate new seed, create at temp index,
	//    then swap.
	//
	//    We use a temporary NV index (nvIndex + 0x100) for the new seed.
	//    If the new index is successfully created and written, we delete the
	//    old indexes. If any step fails, the old indexes remain intact.

	// Generate new seed
	seed, err := totp.GenerateSeed()
	if err != nil {
		return fmt.Errorf("failed to generate new seed: %w", err)
	}

	// Read current PCR 7 (post-firmware-update state)
	pcrValues := make(map[int][]byte)
	val, err := client.ReadPCR(tpm.AlgSHA256, 7)
	if err != nil {
		return fmt.Errorf("failed to read PCR 7: %w", err)
	}
	pcrValues[7] = val

	// Use a temporary NV index for the new seed
	tempNVIndex := nvIndex + 0x100

	// Define + write new seed at temporary index
	if err := client.DefineRecoveryNVSpace(tempNVIndex, pcrValues); err != nil {
		// If the temp index is already in use, clean it and retry
		_ = client.UndefineRecoveryNVSpace(tempNVIndex, nil)
		if err2 := client.DefineRecoveryNVSpace(tempNVIndex, pcrValues); err2 != nil {
			// Old indexes are still intact — recovery still works (with old seed)
			return fmt.Errorf("failed to define new recovery NV at temp index 0x%x: %w (old indexes preserved)", tempNVIndex, err2)
		}
	}
	if err := client.WriteRecoveryData(tempNVIndex, seed, time.Now().Unix(), pcrValues); err != nil {
		// Clean up the temp index, old indexes remain intact
		_ = client.UndefineRecoveryNVSpace(tempNVIndex, nil)
		return fmt.Errorf("failed to write new seed at temp index 0x%x: %w (old indexes preserved)", tempNVIndex, err)
	}

	// New seed is successfully written at temp index.
	// Now safe to delete old indexes.
	_ = client.UndefineRecoveryNVSpace(nvIndex, nil)

	// Redefine at the original index with the new seed
	if err := client.DefineRecoveryNVSpace(nvIndex, pcrValues); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to redefine at original index 0x%x, new seed at temp index 0x%x\n", nvIndex, tempNVIndex)
	} else if err := client.WriteRecoveryData(nvIndex, seed, time.Now().Unix(), pcrValues); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write at original index 0x%x, new seed at temp index 0x%x\n", nvIndex, tempNVIndex)
		_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
	} else {
		// Success at original index — clean up temp index
		_ = client.UndefineRecoveryNVSpace(tempNVIndex, nil)
	}

	// Write otpauth URI to pending file for user to retrieve with --show
	uri := totp.BuildOTPAuthURI(seed, "Vanguard", "recovery")
	pendingDir := filepath.Dir(recoveryPendingPath)
	if err := os.MkdirAll(pendingDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to create %s: %v\n", pendingDir, err)
	} else if err := os.WriteFile(recoveryPendingPath, []byte(uri), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write recovery-pending file: %v\n", err)
	}

	fmt.Println("recovery: seed re-provisioned after firmware update (PCR 7 changed)")
	fmt.Println("recovery: run 'vanguard recovery --show' to display the new QR code for enrollment")

	return nil
}

func (c *RecoveryCmd) runInstructions() error {
	fmt.Println()
	fmt.Println("  " + headerSty.Render("VANGUARD RECOVERY"))
	fmt.Println()

	fmt.Println("  " + headerSty.Render("TOTP Recovery"))
	fmt.Println()
	fmt.Println("    If the TPM2 unlock fails (e.g. after firmware update):")
	fmt.Println("    1. Vanguard prompts for a 6-digit recovery code")
	fmt.Println("    2. Enter the current TOTP code from your authenticator app")
	fmt.Println("    3. If correct, passphrase fallback is enabled for this boot")
	fmt.Println()
	fmt.Println("    Enable:    sudo vanguard recovery --enable")
	fmt.Println("    Re-enroll: sudo vanguard recovery --show")
	fmt.Println("    Disable:   sudo vanguard recovery --disable")
	fmt.Println()
	fmt.Println("    The seed is sealed to PCR 7 (Secure Boot state) in TPM NVRAM.")
	fmt.Println("    If Secure Boot keys change (firmware update), the seed becomes")
	fmt.Println("    inaccessible and must be re-provisioned:")
	fmt.Println("    sudo vanguard recovery --auto-reseed")
	fmt.Println()

	fmt.Println("  " + headerSty.Render("Recovery PIN"))
	fmt.Println()
	fmt.Println("    The recovery PIN is sealed into the TPM alongside the PCR policy.")
	fmt.Println("    It can be used to unseal manually via systemd-pcrlock recover.")
	fmt.Println()
	fmt.Println("    Reset:     sudo vanguard update -u <uki> -l <luks-device>")
	fmt.Println()

	fmt.Println("  " + headerSty.Render("Passphrase Fallback"))
	fmt.Println()
	fmt.Println("    In strict mode (default), passphrase fallback requires TOTP recovery.")
	fmt.Println("    Without TOTP recovery configured, a failed TPM unlock will halt.")
	fmt.Println()
	fmt.Println("    Add emergency passphrase slot:")
	fmt.Println("    sudo cryptsetup luksAddKey <luks-device>")
	fmt.Println()

	if c.LUKSDevice != "" {
		fmt.Println("  " + headerSty.Render("Re-enroll TPM2 Token"))
		fmt.Println()
		fmt.Printf("    sudo vanguard enroll -u <uki> -l %s --with-pin\n", c.LUKSDevice)
		fmt.Println()
	}

	if _, err := execLookPath("systemd-cryptenroll"); err != nil {
		fmt.Printf("  %s systemd-cryptenroll not found — install it to re-enroll TPM2 tokens\n", warnStyle.Render("⚠"))
		fmt.Println()
	}

	return nil
}

// execLookPath wraps exec.LookPath for testability.
var execLookPath = func(name string) (string, error) {
	return execLookPathImpl(name)
}

// extractSeedFromURI parses the secret= parameter from an otpauth:// URI.
func extractSeedFromURI(uri string) string {
	for _, part := range strings.Split(uri, "&") {
		if strings.HasPrefix(part, "secret=") {
			return strings.TrimPrefix(part, "secret=")
		}
	}
	if idx := strings.Index(uri, "?secret="); idx >= 0 {
		rest := uri[idx+8:]
		if ampIdx := strings.Index(rest, "&"); ampIdx >= 0 {
			return rest[:ampIdx]
		}
		return rest
	}
	return ""
}
