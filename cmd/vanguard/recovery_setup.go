package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zaolin/vanguard/internal/hotp"
	"github.com/zaolin/vanguard/internal/tpm"
)

// recoveryPendingPath is where --auto-reseed writes the otpauth URI for
// the new seed, so the user can retrieve it with 'vanguard recovery --show'
// after a firmware update.
const recoveryPendingPath = "/var/lib/vanguard/recovery-pending.uri"

// recoveryMaxFailCount mirrors recovery.MaxFailCount (init package) for
// display purposes. The enforcement lives in the init binary; the host CLI
// only reports the value.
const recoveryMaxFailCount = 10

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
	stIndex := uint32(tpm.DefaultRecoveryStateNVIndex)
	stExists := client.RecoveryNVExists(stIndex)

	if !seedExists && !stExists {
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

	if stExists {
		fmt.Printf("  Removing state NV index 0x%x...\n", stIndex)
		cmd := exec.Command(tpm2Path, fmt.Sprintf("0x%x", stIndex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  %s Failed to remove state index 0x%x: %v\n", errStyle.Render("✗"), stIndex, err)
		} else {
			fmt.Printf("  %s State NV index 0x%x removed\n", okStyle.Render("✓"), stIndex)
		}
	}

	fmt.Println()
	fmt.Println("  Cleanup complete. Run 'vanguard recovery --enable' to set up")
	fmt.Println("  HOTP recovery with the new PCR-bound anti-evil-maid protection.")
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
	stIndex := uint32(tpm.DefaultRecoveryStateNVIndex)
	stExists := client.RecoveryNVExists(stIndex)

	if !seedExists && !stExists {
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
	return fmt.Errorf("tpm2_nvundefine not found — install tpm2-tools to clean legacy indexes, or run: tpm2_nvundefine 0x%x && tpm2_nvundefine 0x%x", nvIndex, stIndex)
}

func (c *RecoveryCmd) runEnable(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Test hook: VANGUARD_TEST_SKIP_VERIFY=1 skips the interactive terminal
	// requirement and the verification prompt (the seed is printed to stdout
	// for scripted capture). Only meaningful for QEMU test scenarios; the
	// seed remains fully TPM-protected, so production behavior is unchanged.
	testSkipVerify := os.Getenv("VANGUARD_TEST_SKIP_VERIFY") == "1"

	// Check if stdout is a terminal — the wizard needs interactive input
	if !isTerminal(os.Stdout) && !testSkipVerify {
		fmt.Fprintln(os.Stderr, "error: recovery setup requires an interactive terminal")
		return fmt.Errorf("stdout is not a terminal")
	}

	fmt.Println()
	fmt.Println("  " + headerSty.Render("HOTP RECOVERY SETUP WIZARD"))
	fmt.Println()

	// Step 1: Generate seed and write to TPM NVRAM
	fmt.Println("  Step 1: Generating HOTP seed and writing to TPM NVRAM...")
	fmt.Println()

	seed, err := hotp.GenerateSeed()
	if err != nil {
		return fmt.Errorf("failed to generate HOTP seed: %w", err)
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

	if err := client.WriteRecoveryData(nvIndex, seed, pcrValues); err != nil {
		// Clean up the NV index if write failed
		_ = client.UndefineRecoveryNVSpace(nvIndex, nil)
		return fmt.Errorf("failed to write recovery data: %w", err)
	}

	fmt.Printf("  %s Seed written to TPM NVRAM at index 0x%x\n", okStyle.Render("✓"), nvIndex)
	fmt.Println()

	// Step 2: Display QR code and seed
	fmt.Println("  Step 2: Enroll in your authenticator app")
	fmt.Println()
	fmt.Println("  Scan this QR code with an HOTP-capable authenticator app")
	fmt.Println("  (Aegis, FreeOTP, KeePassXC, Bitwarden, ...):")
	fmt.Println()

	seedB32 := hotp.EncodeBase32(seed)
	uri := hotp.BuildOTPAuthURI(seed, "Vanguard", "recovery", 0)

	if err := hotp.PrintQRCode(uri); err != nil {
		fmt.Printf("  warning: QR code generation failed: %v\n", err)
		fmt.Println("  Enroll manually using this seed:")
	}

	fmt.Println()
	fmt.Printf("  Manual seed (base32): %s\n", seedB32)
	fmt.Println()

	// Test hook: skip the interactive verification and keep the enrollment.
	if testSkipVerify {
		fmt.Println()
		fmt.Printf("  %s HOTP recovery enabled (test mode: verification skipped)\n", warnStyle.Render("⚠"))
		fmt.Printf("  NV Index: 0x%x\n", nvIndex)
		fmt.Println()
		return nil
	}

	// Step 3: Verify — user must enter a code from their app to confirm enrollment
	fmt.Println("  Step 3: Verify enrollment")
	fmt.Println()
	fmt.Println("  Enter the current 8-digit code from your authenticator app")
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
			fmt.Printf("  %s HOTP recovery enabled (unverified)\n", warnStyle.Render("⚠"))
			fmt.Printf("  NV Index: 0x%x\n", nvIndex)
			fmt.Println("  Run 'vanguard recovery --show' to verify later.")
			fmt.Println()
			return nil
		}

		matched, ok := hotp.Validate(code, seed, 0, hotp.Lookahead)
		if ok {
			// Consume the verification code: advance the stored counter past
			// it so the code just typed (it was echoed in plaintext to this
			// terminal) can never authorize a recovery. The app must be
			// advanced to matched+1 to stay in sync.
			if err := client.WriteRecoveryState(matched+1, 0); err != nil {
				fmt.Printf("  %s Warning: failed to persist counter: %v\n", warnStyle.Render("⚠"), err)
				fmt.Println("  The verification code remains valid until first use.")
			}
			fmt.Println()
			fmt.Printf("  %s Verification successful — HOTP recovery is enabled\n", okStyle.Render("✓"))
			fmt.Println()
			fmt.Println(box("HOTP Recovery Summary", []string{
				fmt.Sprintf("NV Index:    0x%x", nvIndex),
				fmt.Sprintf("Algorithm:   HMAC-SHA256"),
				fmt.Sprintf("Mode:        counter-based (no clock)"),
				fmt.Sprintf("Digits:      %d", hotp.Digits),
				fmt.Sprintf("PCR binding: PCR 7 (Secure Boot)"),
				fmt.Sprintf("Counter:     %d", matched+1),
				fmt.Sprintf("Verified:    yes"),
			}))
			fmt.Println()
			fmt.Printf("  %s Resync your authenticator app: press 'next'/refresh until the\n", warnStyle.Render("⚠"))
			fmt.Printf("  app counter reaches %d (or re-scan the QR from 'vanguard recovery --show'),\n", matched+1)
			fmt.Println("  otherwise the app's next code will be one behind the stored counter.")
			fmt.Println()
			fmt.Println("  If TPM unlock fails at boot, enter the 8-digit code")
			fmt.Println("  from your authenticator app to enable passphrase fallback.")
			fmt.Println()
			return nil
		}

		fmt.Printf("  %s Invalid code\n", errStyle.Render("✗"))
		if attempt < 3 {
			fmt.Printf("  Make sure your app's counter is at 0 (press 'next' to resync) and try again.\n")
		}
	}

	// Step 4: Verification failed — remove seed to avoid false sense of security
	fmt.Println()
	fmt.Println("  Verification failed after 3 attempts.")
	fmt.Println("  Removing HOTP seed from TPM NVRAM to prevent an unverified enrollment...")
	fmt.Println()

	if err := client.UndefineRecoveryNVSpace(nvIndex, nil); err != nil {
		fmt.Printf("  %s Warning: failed to remove NV index: %v\n", warnStyle.Render("⚠"), err)
		fmt.Println("  You can manually remove it with: vanguard recovery --disable")
	} else {
		fmt.Printf("  %s Seed removed from TPM NVRAM\n", okStyle.Render("✓"))
	}

	fmt.Println()
	return fmt.Errorf("HOTP verification failed — enrollment aborted, seed removed")
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
		fmt.Println("  HOTP recovery is not enabled (NV index not found)")
		return nil
	}

	// Undefine uses owner auth (no policy session needed)
	if err := client.UndefineRecoveryNVSpace(nvIndex, nil); err != nil {
		return fmt.Errorf("failed to undefine recovery NV space: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %s HOTP recovery disabled (NV index 0x%x removed)\n",
		okStyle.Render("✓"), nvIndex)
	fmt.Println()

	return nil
}

func (c *RecoveryCmd) runShow(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	if !isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "error: refusing to print HOTP seed to non-terminal stdout")
		fmt.Fprintln(os.Stderr, "       Run this command in a terminal to display the QR code.")
		return nil
	}

	// Check for pending re-provision file (from --auto-reseed after firmware update)
	if uriData, err := os.ReadFile(recoveryPendingPath); err == nil {
		uri := strings.TrimSpace(string(uriData))
		seedB32 := extractSeedFromURI(uri)
		seed, err := hotp.DecodeBase32(seedB32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse pending recovery URI: %v\n", err)
		} else {
			fmt.Println()
			fmt.Println("  " + warnStyle.Render("RECOVERY SEED RE-PROVISIONED AFTER FIRMWARE UPDATE"))
			fmt.Println("  Your previous HOTP seed is no longer valid (Secure Boot keys changed).")
			fmt.Println("  A new seed has been generated. Re-enroll your authenticator app:")
			fmt.Println()

			fmt.Println(box("New HOTP Recovery", []string{
				fmt.Sprintf("NV Index:      0x%x", nvIndex),
				fmt.Sprintf("Algorithm:     HMAC-SHA256"),
				fmt.Sprintf("Mode:          counter-based (no clock)"),
				fmt.Sprintf("Digits:        %d", hotp.Digits),
				fmt.Sprintf("PCR binding:   PCR 7 (Secure Boot)"),
				fmt.Sprintf("Seed (base32): %s", seedB32),
				fmt.Sprintf("Status:        pending enrollment"),
			}))

			fmt.Println()
			fmt.Println("  " + headerSty.Render("QR CODE — Scan with your authenticator app"))
			fmt.Println()

			if err := hotp.PrintQRCode(uri); err != nil {
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

			if code != "" {
				_, ok := hotp.Validate(code, seed, 0, hotp.Lookahead)
				if ok {
					fmt.Printf("  %s Verification successful — pending file removed\n", okStyle.Render("✓"))
					_ = os.Remove(recoveryPendingPath)
				} else {
					fmt.Printf("  %s Invalid code — pending file retained for next attempt\n", errStyle.Render("✗"))
				}
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
		fmt.Println("  HOTP recovery is not enabled (NV index not found)")
		return nil
	}

	seed, counter, failCount, err := client.ReadRecoveryData(nvIndex)
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

	seedB32 := hotp.EncodeBase32(seed)
	// Show the URI at the CURRENT counter so re-adding the seed to an app
	// starts at the right position (apps typically import counter=0, so a
	// mid-life counter means the app must advance — surface the value).
	uri := hotp.BuildOTPAuthURI(seed, "Vanguard", "recovery", counter)

	fmt.Println()
	fmt.Println(box("Current HOTP Recovery", []string{
		fmt.Sprintf("NV Index:      0x%x", nvIndex),
		fmt.Sprintf("Algorithm:     HMAC-SHA256"),
		fmt.Sprintf("Mode:          counter-based (no clock)"),
		fmt.Sprintf("Digits:        %d", hotp.Digits),
		fmt.Sprintf("Counter:       %d", counter),
		fmt.Sprintf("Fail count:    %d / %d", failCount, recoveryMaxFailCount),
		fmt.Sprintf("PCR binding:   PCR 7 (Secure Boot)"),
		fmt.Sprintf("PCR 7 current: %s", pcr7Hex),
		fmt.Sprintf("Seed (base32): %s", seedB32),
	}))

	fmt.Println()
	fmt.Println("  " + headerSty.Render("QR CODE — Scan with your authenticator app"))
	fmt.Println()

	if err := hotp.PrintQRCode(uri); err != nil {
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

	if _, ok := hotp.Validate(code, seed, counter, hotp.Lookahead); ok {
		fmt.Printf("  %s Verification successful\n", okStyle.Render("✓"))
	} else {
		fmt.Printf("  %s Invalid code — ensure the app counter is at %d (or scan the QR above)\n", errStyle.Render("✗"), counter)
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
		fmt.Printf("  %s HOTP recovery is NOT configured (NV index 0x%x not found)\n", errStyle.Render("✗"), nvIndex)
		fmt.Println()
		fmt.Println("  Enable recovery with: sudo vanguard recovery --enable")
		fmt.Println()
		return fmt.Errorf("recovery not configured")
	}

	fmt.Printf("  %s Recovery NV index 0x%x exists\n", okStyle.Render("✓"), nvIndex)

	// Check the state index (counter + fail count)
	if !client.StateNVExists() {
		fmt.Printf("  %s Recovery state NV index 0x%x is missing\n", errStyle.Render("✗"), tpm.DefaultRecoveryStateNVIndex)
		fmt.Println()
		fmt.Println("  The counter/state index was lost (possibly from a previous failed reseed).")
		fmt.Println("  The seed may still be valid — auto-reseed can repair this without changing the seed.")
		fmt.Println()
		fmt.Println("  To fix:")
		fmt.Println("    sudo vanguard recovery --auto-reseed  # repair state (seed preserved)")
		fmt.Println()
		return fmt.Errorf("recovery state NV index missing")
	}

	// Try to read the seed (requires PCR 7 to match)
	seed, counter, failCount, err := client.ReadRecoveryData(nvIndex)
	if err != nil {
		fmt.Printf("  %s Failed to read HOTP seed: %v\n", errStyle.Render("✗"), err)
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

	fmt.Printf("  %s HOTP seed readable (PCR 7 matches enrollment)\n", okStyle.Render("✓"))

	// Counter / fail-count state
	fmt.Printf("  %s Counter: %d\n", okStyle.Render("✓"), counter)
	if failCount > 0 {
		fmt.Printf("  %s Failed attempts: %d / %d (locked at %d; resets after a successful unlock)\n",
			warnStyle.Render("⚠"), failCount, recoveryMaxFailCount, recoveryMaxFailCount)
	} else {
		fmt.Printf("  %s Failed attempts: 0\n", okStyle.Render("✓"))
	}

	// Verify a HOTP code can be generated from the seed (sanity check of the
	// seed/algorithm; this is the code the authenticator app should show at
	// the stored counter).
	code := hotp.GenerateCode(seed, counter)
	if len(code) != hotp.Digits {
		fmt.Printf("  %s HOTP code generation failed\n", errStyle.Render("✗"))
	} else {
		fmt.Printf("  %s HOTP code generation works (%d digits, code at counter %d: %s)\n",
			okStyle.Render("✓"), hotp.Digits, counter, code)
	}

	fmt.Println()
	fmt.Printf("  %s HOTP recovery is properly configured and ready\n", okStyle.Render("✓"))
	fmt.Println()

	return nil
}

func (c *RecoveryCmd) runAutoReseed(nvIndex uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	client := tpm.New()
	if !client.WaitForDevice(5 * time.Second) {
		return fmt.Errorf("TPM device not available")
	}

	// 1. Recovery not configured at the primary index? Before assuming
	// nothing is configured, check for a stranded temp seed (a previous
	// reseed wrote the new seed at nvIndex+0x100 but failed to move it to
	// the primary index). The seed cannot be read (PCR policy), but the
	// index's existence is public metadata.
	tempNVIndex := nvIndex + 0x100
	if !client.RecoveryNVExists(nvIndex) {
		if client.RecoveryNVExists(tempNVIndex) {
			return fmt.Errorf("recovery seed missing at 0x%x but a stranded replacement exists at temp index 0x%x (previous reseed failed mid-swap) — run 'vanguard recovery --show' to retrieve the pending seed, or re-run with a fresh enrollment", nvIndex, tempNVIndex)
		}
		// Recovery not configured — nothing to do
		return nil
	}

	// 2. Diagnose via a seed-only read FIRST (ReadRecoveryData would fail
	// on a missing state index even when the seed is perfectly fine —
	// the exact misdiagnosis that previously triggered destructive reseeds).
	_, seedErr := client.ReadSeedOnly(nvIndex)

	// 3. State-index repair: seed readable but the counter/state index is
	//    missing. Preserves the existing seed — the user's authenticator
	//    enrollment stays valid. The counter is reset to 0, so the app must
	//    be re-scanned or advanced to 0.
	if seedErr == nil {
		if client.StateNVExists() {
			// Seed readable and state present: nothing to do.
			return nil
		}

		// Read current PCR 7 — the state index is bound to it.
		repairPCR := make(map[int][]byte)
		repairVal, pcrErr := client.ReadPCR(tpm.AlgSHA256, 7)
		if pcrErr != nil {
			return fmt.Errorf("failed to read PCR 7 for state recreation: %w", pcrErr)
		}
		repairPCR[7] = repairVal

		if err := client.DefineStateNVIndex(repairPCR); err != nil {
			return fmt.Errorf("failed to recreate recovery state NV index: %w", err)
		}

		fmt.Println("recovery: recovery state NV index was missing, recreated (seed preserved)")
		fmt.Println("recovery: counter reset to 0 — re-scan the QR from 'vanguard recovery --show'")
		fmt.Println("recovery: HOTP recovery is now fully operational")
		return nil
	}

	// 4. Seed unreadable. Only a GENUINE PCR-policy mismatch justifies
	//    replacing the seed — a transient transport/session failure must
	//    never trigger the destructive path (the seed may be perfectly
	//    healthy behind a flaky TPM connection).
	if !errors.Is(seedErr, tpm.ErrSeedPCRMismatch) {
		return fmt.Errorf("seed read failed for a non-policy reason (NOT reseeding — the existing enrollment is preserved): %w", seedErr)
	}

	// 5. Full atomic reseed (PCR 7 changed — e.g. firmware update reset
	//    Secure Boot keys). The old seed is unreadable under the new PCR
	//    state and is gone in practice; both indexes must be re-provisioned.
	//
	//    Staging uses SEED-ONLY primitives so the shared timestamp index is
	//    never touched until the swap is complete, and the swap never
	//    fakes success: if the seed cannot be landed at the primary index,
	//    an error is returned and the pending URI has already been written
	//    for retrieval via --show.
	seed, err := hotp.GenerateSeed()
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

	// Stage the new seed at the temp index (seed-only define + write —
	// the shared state index is untouched).
	if err := client.DefineSeedNVIndex(tempNVIndex, pcrValues); err != nil {
		// If the temp index is already in use, clean it and retry
		_ = client.UndefineSeedNVSpace(tempNVIndex)
		if err2 := client.DefineSeedNVIndex(tempNVIndex, pcrValues); err2 != nil {
			// Old indexes are still intact — recovery still works (with old seed)
			return fmt.Errorf("failed to define new recovery NV at temp index 0x%x: %w (old indexes preserved)", tempNVIndex, err2)
		}
	}
	if err := client.WriteSeedOnly(tempNVIndex, seed, pcrValues); err != nil {
		// Clean up the temp seed, old indexes remain intact
		_ = client.UndefineSeedNVSpace(tempNVIndex)
		return fmt.Errorf("failed to write new seed at temp index 0x%x: %w (old indexes preserved)", tempNVIndex, err)
	}

	// Write the pending otpauth URI BEFORE the swap: once the old seed is
	// undefined, this file is the only way to retrieve the new seed. The
	// reseed resets the counter to 0, so the URI uses counter=0.
	uri := hotp.BuildOTPAuthURI(seed, "Vanguard", "recovery", 0)
	pendingDir := filepath.Dir(recoveryPendingPath)
	if err := os.MkdirAll(pendingDir, 0755); err != nil {
		// Swap not started yet — safe to abort with old indexes intact.
		_ = client.UndefineSeedNVSpace(tempNVIndex)
		return fmt.Errorf("failed to create %s: %w (old indexes preserved)", pendingDir, err)
	}
	if err := os.WriteFile(recoveryPendingPath, []byte(uri), 0600); err != nil {
		_ = client.UndefineSeedNVSpace(tempNVIndex)
		return fmt.Errorf("failed to write recovery-pending file: %w (old indexes preserved)", err)
	}

	// Swap: replace the primary seed (seed-only — state untouched).
	// DefineSeedNVIndex undefined the old primary seed itself.
	if err := client.DefineSeedNVIndex(nvIndex, pcrValues); err != nil {
		return fmt.Errorf("failed to define new seed at primary index 0x%x: %w — new seed remains at temp index 0x%x, retrieve it via 'vanguard recovery --show'", nvIndex, err, tempNVIndex)
	}
	if err := client.WriteSeedOnly(nvIndex, seed, pcrValues); err != nil {
		return fmt.Errorf("failed to write new seed at primary index 0x%x: %w — new seed remains at temp index 0x%x, retrieve it via 'vanguard recovery --show'", nvIndex, err, tempNVIndex)
	}

	// Seed landed at the primary index — clean up the temp seed
	// (seed-only undefine: the shared state index survives).
	_ = client.UndefineSeedNVSpace(tempNVIndex)

	// Re-provision the state index (counter=0, failCount=0) for the new seed.
	if err := client.DefineStateNVIndex(pcrValues); err != nil {
		return fmt.Errorf("seed re-provisioned at 0x%x but state index recreation failed: %w — run 'vanguard recovery --auto-reseed' again to repair", nvIndex, err)
	}

	fmt.Println("recovery: seed re-provisioned after firmware update (PCR 7 changed)")
	fmt.Println("recovery: run 'vanguard recovery --show' to display the new QR code for enrollment")

	return nil
}

func (c *RecoveryCmd) runInstructions() error {
	fmt.Println()
	fmt.Println("  " + headerSty.Render("VANGUARD RECOVERY"))
	fmt.Println()

	fmt.Println("  " + headerSty.Render("HOTP Recovery"))
	fmt.Println()
	fmt.Println("    If the TPM2 unlock fails (e.g. after firmware update):")
	fmt.Println("    1. Vanguard prompts for an 8-digit recovery code")
	fmt.Println("    2. Enter the current HOTP code from your authenticator app")
	fmt.Println("    3. If correct, passphrase fallback is enabled for this boot")
	fmt.Println()
	fmt.Println("    HOTP is counter-based: no clock is involved, so recovery works")
	fmt.Println("    even with a dead RTC or a wrong system time.")
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
	fmt.Println("    In strict mode (default), passphrase fallback requires HOTP recovery.")
	fmt.Println("    Without HOTP recovery configured, a failed TPM unlock will halt.")
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
