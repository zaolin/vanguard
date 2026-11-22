package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zaolin/vanguard/internal/config"
	"github.com/zaolin/vanguard/internal/pcrlock"
)

func (c *UpdatePolicyCmd) Run() error {
	pcrlock.Verbose = c.Verbose

	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Load config file if specified — CLI flags override TOML values
	if c.Config != "" {
		cfg, err := config.Load(c.Config)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %w", c.Config, err)
		}
		if c.UKIPath == "" {
			c.UKIPath = cfg.UKIPath
		}
		if c.LUKSDevice == "" {
			c.LUKSDevice = cfg.LUKSDevice
		}
	}

	if c.UKIPath == "" {
		return fmt.Errorf("UKI path required: use -u <path> or set uki_path in config file")
	}

	if _, err := os.Stat(c.UKIPath); err != nil {
		return fmt.Errorf("UKI file not found: %s", c.UKIPath)
	}

	if c.DryRun {
		fmt.Println()
		fmt.Println("  " + headerSty.Render("DRY RUN — no changes will be made"))
		fmt.Println()
		fmt.Printf("  UKI:          %s\n", c.UKIPath)
		fmt.Printf("  Policy:       %s\n", c.PolicyOutput)
		if c.LUKSDevice != "" {
			fmt.Printf("  LUKS device:  %s\n", c.LUKSDevice)
		}
		fmt.Printf("  GPT binding:  %v\n", c.LUKSDevice != "" && !c.NoGPT)
		fmt.Printf("  Cleanup:      %v\n", c.Cleanup)
		fmt.Println()
		fmt.Println("  Would: configure masks, regenerate firmware components,")
		fmt.Println("        lock Secure Boot, lock UKI, generate policy, verify.")
		fmt.Println()
		return nil
	}

	if c.PolicyOutput == "" {
		c.PolicyOutput = policyPathForUKI(c.UKIPath)
	}

	// Validate the repair flags before touching the TPM: an unsupported
	// --repair-unlock method must be rejected before the policy (and the NV
	// index) is regenerated, not after the system was already mutated.
	if c.RepairToken {
		if _, err := c.repairUnlockArgs(repairUnlockPassphrase); err != nil {
			return err
		}
	}

	if _, err := os.Stat(pcrlock.PCRLockBinPath()); err != nil {
		return fmt.Errorf("systemd-pcrlock not found at %s", pcrlock.PCRLockBinPath())
	}

	fmt.Println()
	fmt.Println("  " + headerSty.Render("UPDATING TPM POLICY"))
	fmt.Println()

	results := &updateResults{}

	if c.Verbose {
		fmt.Println(dimStyle.Render(box("PCR Masks", []string{"Configuring PCR masks..."})))
	}
	if err := pcrlock.ConfigureMasks(); err != nil {
		return fmt.Errorf("failed to configure masks: %w", err)
	}

	// Regenerate stale firmware components from the current boot's event log.
	// Without this, a stale 250-firmware-code-early/generated.pcrlock (e.g. from
	// a previous firmware version) causes systemd-pcrlock to drop PCR 0/1, which
	// cascades to drop ALL PCRs — including PCR 7 — producing
	// "PCR 7 missing from policy". See docs/tpm2-setup.md for details.
	if c.Verbose {
		fmt.Println(dimStyle.Render(box("Firmware Components", []string{"Regenerating from current event log..."})))
	}
	if err := pcrlock.RegenerateFirmwareComponents(); err != nil {
		return fmt.Errorf("failed to regenerate firmware components: %w", err)
	}

	fmt.Println(box("Lock PCRs", []string{
		fmt.Sprintf("%s PCR 7  secure-boot-policy", okStyle.Render("✓")),
	}))
	if err := pcrlock.LockSecureBoot(); err != nil {
		return fmt.Errorf("failed to lock secure boot: %w", err)
	}
	results.pcr7Locked = true

	gptEnabled := c.LUKSDevice != "" && !c.NoGPT

	if gptEnabled {
		gptDevice := getParentDisk(c.LUKSDevice)
		if err := pcrlock.LockGPT(gptDevice); err != nil {
			if err == pcrlock.ErrNoGPT {
				gptEnabled = false
				fmt.Printf("Note: PCR 5 (GPT) not locked: %v — the disk behind %s is not GPT-partitioned\n", err, c.LUKSDevice)
				if err := pcrlock.MaskPolicy("600-gpt.pcrlock"); err != nil {
					if c.Verbose {
						fmt.Printf("Note: failed to mask GPT policy: %v\n", err)
					}
				}
			} else {
				return fmt.Errorf("failed to lock GPT: %w", err)
			}
		} else {
			if err := pcrlock.LockEFIActions(); err != nil {
				if c.Verbose {
					fmt.Printf("Note: failed to lock EFI actions: %v\n", err)
				}
			}
		}
	} else {
		if err := pcrlock.MaskPolicy("600-gpt.pcrlock"); err != nil {
			if c.Verbose {
				fmt.Printf("Note: failed to mask GPT policy: %v\n", err)
			}
		}
	}

	c.luksHeaderEnabled = c.LUKSDevice != "" && !c.NoLUKSHeader
	luksHeaderEnabled := c.luksHeaderEnabled

	if luksHeaderEnabled {
		if err := pcrlock.LockLUKSHeader(c.LUKSDevice); err != nil {
			if c.Verbose {
				fmt.Printf("Note: failed to lock LUKS header: %v\n", err)
			}
			luksHeaderEnabled = false
			if err := pcrlock.MaskLUKSHeader(); err != nil {
				if c.Verbose {
					fmt.Printf("Note: failed to mask LUKS header policy: %v\n", err)
				}
			}
		}
	} else {
		if err := pcrlock.MaskLUKSHeader(); err != nil {
			if c.Verbose {
				fmt.Printf("Note: failed to mask LUKS header policy: %v\n", err)
			}
		}
	}

	// The repair flow must use the EFFECTIVE decision (after the fallback
	// above), not the requested one: refreshing a prediction for a masked
	// header binding would contradict the summary.
	c.luksHeaderEnabled = luksHeaderEnabled
	if err := pcrlock.LockUKIWithPEFallback(c.UKIPath); err != nil {
		return fmt.Errorf("failed to lock UKI: %w", err)
	}

	{
		var lockLines []string
		addPCR := func(pcr int, name string, locked bool) {
			if locked {
				lockLines = append(lockLines, fmt.Sprintf("%s PCR %d  %s", okStyle.Render("✓"), pcr, name))
			} else {
				lockLines = append(lockLines, fmt.Sprintf("%s PCR %d  %s", dimStyle.Render("—"), pcr, name))
			}
		}
		addPCR(7, "secure-boot", results.pcr7Locked)
		addPCR(4, "boot-loader", true)
		if gptEnabled {
			addPCR(5, "GPT partition", true)
		}
		if luksHeaderEnabled {
			addPCR(11, "LUKS header", true)
		}
		fmt.Println(box("PCRs Locked", lockLines))
	}

	fmt.Println(box("Make Policy", []string{
		"Enter Recovery PIN when prompted:",
	}))
	if err := pcrlock.MakePolicy(c.PolicyOutput, c.LUKSDevice); err != nil {
		return fmt.Errorf("failed to generate policy: %w", err)
	}

	// Inject the NEW LUKS header prediction into the policy.
	// make-policy generates the policy using the event log (which has the
	// OLD LUKS header hash from the last boot). But the NEXT boot will use
	// the NEW hash (because vanguard update just re-enrolled the TPM2 token,
	// changing the LUKS2 JSON metadata). InjectLUKSHeaderPrediction adds
	// the NEW predicted PCR 11 value so the next boot's unseal succeeds.
	//
	// A failure here is not cosmetic: without the prediction the next boot
	// cannot unseal. It must not be hidden behind --verbose.
	if luksHeaderEnabled {
		if err := pcrlock.InjectLUKSHeaderPrediction(c.PolicyOutput, c.LUKSDevice); err != nil {
			return fmt.Errorf("failed to inject the LUKS header prediction into the policy (the next boot may not unseal): %w", err)
		}
	}

	if !c.NoVerify {
		requiredPCRs := []int{7}

		verifyErr := pcrlock.VerifyPolicy(c.PolicyOutput, requiredPCRs)

		pcrs, _ := pcrlock.Predict(c.PolicyOutput)
		var verifyLines []string
		for _, p := range []int{2, 3, 4, 5, 7, 11} {
			name := pcrName(p)
			if pcrs[p] {
				verifyLines = append(verifyLines, fmt.Sprintf("%s PCR %d  %s", okStyle.Render("✓"), p, name))
			} else if (p == 7) || (p == 5 && gptEnabled) || (p == 11 && luksHeaderEnabled) {
				verifyLines = append(verifyLines, fmt.Sprintf("%s PCR %d  %s  %s", errStyle.Render("✗"), p, name, errStyle.Render("missing")))
			} else {
				verifyLines = append(verifyLines, fmt.Sprintf("%s PCR %d  %s", dimStyle.Render("—"), p, name))
			}
		}
		fmt.Println(box("Verify", verifyLines))

		if gptEnabled {
			if !pcrs[5] {
				fmt.Println(box("", []string{
					warnStyle.Render("PCR 5 (GPT) requested but not in policy"),
					dimStyle.Render("Unpredictable firmware events prevented inclusion"),
				}))
			}
		}

		if verifyErr != nil {
			return fmt.Errorf("policy verification failed: %w", verifyErr)
		}
	}

	policyNVIndex, err := pcrlock.GetPolicyNVIndex(c.PolicyOutput)
	if err != nil {
		return fmt.Errorf("failed to read policy NV index: %w", err)
	}

	pcrs, _ := pcrlock.Predict(c.PolicyOutput)

	var summaryLines []string
	summaryLines = append(summaryLines, fmt.Sprintf("NV Index:     0x%x", policyNVIndex))
	summaryLines = append(summaryLines, fmt.Sprintf("Policy:       %s", c.PolicyOutput))

	var activePCRs []string
	for _, p := range []int{2, 3, 4, 5, 7} {
		if pcrs[p] {
			activePCRs = append(activePCRs, fmt.Sprintf("%d", p))
		}
	}
	summaryLines = append(summaryLines, fmt.Sprintf("Active PCRs:  %s", strings.Join(activePCRs, ", ")))

	// Token state, used below for --repair-token.
	//
	// Staleness is decided by comparing the serialized ESYS_TR of the
	// pcrlock NV index: the token's tpm2_pcrlock_nv blob against the
	// policy's nvHandle blob. systemd matches the two byte by byte to find
	// the policy that belongs to a token, so this answers exactly the
	// question at hand: does the token still point at the NV index the
	// freshly generated policy describes?
	//
	// A policy regeneration undefines and redefines the NV index. The new
	// definition can carry a different public area (a fresh recovery PIN),
	// which changes the NV name — and the sealed blob binds that name, so
	// the old token can no longer unseal although the index number is
	// unchanged. An identical definition leaves the token valid, which the
	// blob comparison below reports correctly.
	tokenIsStale := false     // no LUKS device → nothing to repair
	tokenUndecidable := false // token state could not be determined

	if c.LUKSDevice != "" {
		token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice)
		if err != nil {
			summaryLines = append(summaryLines, warnStyle.Render(fmt.Sprintf("Token:        not found on %s", c.LUKSDevice)))
		} else {
			newPolicy, policyErr := pcrlock.ParsePolicy(c.PolicyOutput)
			if policyErr != nil {
				return fmt.Errorf("failed to parse policy for token comparison: %w", policyErr)
			}
			stale, staleErr := pcrlock.TokenMatchesPolicy(token, newPolicy)
			switch {
			case staleErr != nil:
				// The token's usability cannot be verified (no nvHandle,
				// a hybrid PCR+pcrlock token, an unreadable blob).
				// Neither claim "OK" nor trigger a repair: the state is
				// unknown, and the user must decide.
				tokenUndecidable = true
				summaryLines = append(summaryLines, warnStyle.Render(fmt.Sprintf("Token:        cannot verify — %v", staleErr)))
			case stale:
				tokenIsStale = true
				summaryLines = append(summaryLines, errStyle.Render(fmt.Sprintf(
					"Token stale! The token is bound to a previous state of NV index 0x%x and can no longer unseal", token.NVIndex)))
			case token.NVHandle == "":
				// Classic PCR-bound token: the pcrlock NV index does not
				// apply to it, so there is nothing to repair.
				summaryLines = append(summaryLines, fmt.Sprintf("Token:        %s (not pcrlock-bound)", okStyle.Render("OK")))
			default:
				summaryLines = append(summaryLines, fmt.Sprintf("Token:        %s (NV matches)", okStyle.Render("OK")))
			}
			// Undecidable tokens always get the manual instructions: no
			// automatic repair runs for them, even with --repair-token.
			if tokenUndecidable || (tokenIsStale && !c.RepairToken) {
				summaryLines = append(summaryLines, "")
				summaryLines = append(summaryLines, dimStyle.Render("Re-enroll token:"))
				summaryLines = append(summaryLines, dimStyle.Render(fmt.Sprintf(" systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto")))
				summaryLines = append(summaryLines, dimStyle.Render(fmt.Sprintf("   --tpm2-with-pin=yes --tpm2-pcrlock=%s %s", c.PolicyOutput, c.LUKSDevice)))
				if tokenIsStale {
					summaryLines = append(summaryLines, dimStyle.Render("Or re-run with --repair-token to do this automatically."))
				}
			}
		}
	}

	if !pcrs[7] {
		summaryLines = append(summaryLines, "")
		summaryLines = append(summaryLines, errStyle.Render("PCR 7 (Secure Boot) not in policy!"))
	}
	if !pcrs[4] {
		summaryLines = append(summaryLines, dimStyle.Render("PCR 4 (boot-loader) not in policy — firmware events unpredictable"))
	}

	fmt.Println(box("Summary", summaryLines))

	// Repair a token that no longer matches the regenerated policy. The
	// sealed blob's authPolicy binds the OLD index's NV name, so no
	// in-place re-pointing is possible — the blob must be re-sealed, which
	// is exactly what systemd-cryptenroll does. Do it automatically when
	// asked.
	if c.RepairToken && tokenIsStale {
		if err := c.repairToken(policyNVIndex); err != nil {
			return err
		}
	}

	if c.Cleanup {
		keepIndices := []int{policyNVIndex}
		if c.LUKSDevice != "" {
			if token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice); err == nil && token.NVIndex != 0 && token.NVIndex != policyNVIndex {
				keepIndices = append(keepIndices, token.NVIndex)
			}
		}
		removed, _ := pcrlock.CleanupOldNVIndices(keepIndices)
		if removed > 0 {
			fmt.Println(box("Cleanup", []string{
				fmt.Sprintf("%s Removed %d old NV index(es)", okStyle.Render("✓"), removed),
			}))
		}
	}

	newPolicy, err := pcrlock.ParsePolicy(c.PolicyOutput)
	if err == nil {
		var integrityLines []string

		_, nvMatch, nvErr := pcrlock.VerifyNVIndex(newPolicy)
		if nvErr != nil {
			integrityLines = append(integrityLines, errStyle.Render(fmt.Sprintf("✗ NV check failed: %v", nvErr)))
		} else if nvMatch {
			integrityLines = append(integrityLines, fmt.Sprintf("%s NV index synchronized", okStyle.Render("✓")))
		} else {
			integrityLines = append(integrityLines, errStyle.Render("✗ NV index mismatch"))
		}

		pcrMatches, currentValues, pcrErr := pcrlock.VerifyPCRs(newPolicy)
		if pcrErr != nil {
			integrityLines = append(integrityLines, errStyle.Render(fmt.Sprintf("✗ PCR check failed: %v", pcrErr)))
		} else {
			// Build an enforcement map (PCR → enforced?) with the same
			// IsEnforcedValues semantics as vanguard verify/status, so
			// unbound PCRs render as informational instead of alarming
			// "mismatch" rows (e.g. PCR 14 shim-policy, all-zeros by
			// design).
			enforced := make(map[int]bool)
			for _, pv := range newPolicy.PCRValues {
				enforced[pv.PCR] = pcrlock.IsEnforcedValues(pv.Values)
			}

			pcrFailures := 0
			// Deterministic PCR order for stable output
			pcrList := make([]int, 0, len(pcrMatches))
			for p := range pcrMatches {
				pcrList = append(pcrList, p)
			}
			sort.Ints(pcrList)
			for _, p := range pcrList {
				match := pcrMatches[p]
				// PCR 11: the policy predicts the at-unseal-time value and
				// systemd extends PCR 11 after unlock, so the live comparison
				// always mismatches in a booted system. Use the header digest
				// binding when the device is available; the digest was just
				// written from this device, so match is the expected outcome.
				if p == 11 && !match && c.LUKSDevice != "" {
					hb, hbErr := pcrlock.VerifyLUKSHeaderBinding(c.LUKSDevice)
					if hbErr == nil && hb.Bound {
						match = hb.Match
					}
				}
				if !match && !enforced[p] {
					// Unbound PCR (e.g. all-zeros prediction): informational.
					integrityLines = append(integrityLines,
						dimStyle.Render(fmt.Sprintf("— PCR %-2d unbound (all-zeros prediction, not enforced)", p)))
					continue
				}
				if !match {
					pcrFailures++
					current := currentValues[p]
					if current == "" {
						current = "(unreadable)"
					}
					integrityLines = append(integrityLines, errStyle.Render(fmt.Sprintf("✗ PCR %d mismatch (current: %s)", p, current)))
				}
			}
			if pcrFailures == 0 {
				integrityLines = append(integrityLines, fmt.Sprintf("%s All PCR values match", okStyle.Render("✓")))
			}
		}

		fmt.Println(box("Integrity Check", integrityLines))
	}

	fmt.Println()
	fmt.Printf("  %s\n", dimStyle.Render(fmt.Sprintf("Policy written to: %s", c.PolicyOutput)))
	fmt.Println()

	return nil
}

type updateResults struct {
	pcr7Locked bool
}

// Seams for the repair flow, so its ordering and verification can be tested
// without a TPM or a LUKS device.
var (
	getLUKSTPMToken        = pcrlock.GetLUKSTPMToken
	injectHeaderPrediction = pcrlock.InjectLUKSHeaderPrediction
	cryptenrollLookPath    = func() (string, error) { return exec.LookPath("systemd-cryptenroll") }
	// stdinIsTerminal reports whether a passphrase prompt can be answered.
	// It is a variable so both repair branches can be tested.
	stdinIsTerminal = func() bool { return isTerminal(os.Stdin) }
)

// repairRunner executes systemd-cryptenroll with the given arguments. It is
// a package variable so the repair flow can be tested without a TPM.
var repairRunner = func(cryptenroll string, args []string) error {
	cmd := exec.Command(cryptenroll, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// repairUnlockMethod describes how the volume is unlocked for the re-seal.
type repairUnlockMethod int

const (
	// repairUnlockPassphrase prompts for the disk passphrase.
	repairUnlockPassphrase repairUnlockMethod = iota
	// repairUnlockTPM2Token unlocks with the existing TPM2 token (systemd
	// 256+), which needs no passphrase.
	repairUnlockTPM2Token
)

// repairUnlockArgs returns the systemd-cryptenroll arguments for the chosen
// unlock method.
//
// Only real cryptenroll options may be produced: cryptenroll knows
// --unlock-key-file, --unlock-fido2-device and --unlock-tpm2-device, and
// nothing like --unlock-password or --unlock-empty. An unsupported method is
// rejected here instead of surfacing as a cryptenroll "Unknown option".
func (c *UpdatePolicyCmd) repairUnlockArgs(method repairUnlockMethod) ([]string, error) {
	if method == repairUnlockTPM2Token {
		return []string{"--unlock-tpm2-device=auto"}, nil
	}

	switch c.RepairUnlock {
	case "", "password":
		// No explicit method: cryptenroll prompts for the passphrase.
		return nil, nil
	case "key-file", "fido2-device", "tpm2-device":
		if c.RepairUnlockValue == "" {
			return nil, fmt.Errorf("--repair-unlock=%s requires --repair-unlock-value", c.RepairUnlock)
		}
		return []string{"--unlock-" + c.RepairUnlock + "=" + c.RepairUnlockValue}, nil
	default:
		return nil, fmt.Errorf("--repair-unlock: unsupported method %q (supported: key-file, fido2-device, tpm2-device; omit for a passphrase prompt)", c.RepairUnlock)
	}
}

// manualRepairMessage is the operator-facing instruction for the
// unattended case, where the token cannot be re-sealed automatically.
func manualRepairMessage(luksDevice, ukiPath, policyPath string) string {
	uki := ukiPath
	if uki == "" {
		uki = "<uki>"
	}
	return fmt.Sprintf(
		"the LUKS token on %s cannot be re-sealed automatically: it no longer matches the regenerated policy "+
			"(e.g. after a firmware/Secure Boot update changed PCR 7), and this run has no terminal for the "+
			"passphrase. Re-enroll the token manually:\n"+
			"  sudo vanguard enroll -u %s -l %s\n"+
			"or:\n"+
			"  sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrlock=%s %s",
		luksDevice, uki, luksDevice, policyPath, luksDevice)
}

// repairToken re-seals the LUKS token against the freshly generated
// policy. The sealed blob's authPolicy binds the OLD index's NV name, so
// the blob must be re-sealed — which is what systemd-cryptenroll does.
func (c *UpdatePolicyCmd) repairToken(policyNVIndex int) error {
	fmt.Println()
	fmt.Println("  " + headerSty.Render("REPAIRING LUKS TOKEN"))
	fmt.Println()
	fmt.Printf("  Token no longer matches the policy (NV index 0x%x).\n", policyNVIndex)

	cryptenroll, lookErr := cryptenrollLookPath()
	if lookErr != nil {
		return fmt.Errorf("--repair-token: systemd-cryptenroll not found — install systemd with cryptsetup support")
	}

	// Unlock method: prefer unlocking the volume with the EXISTING TPM2
	// token (--unlock-tpm2-device=auto, systemd 256+). That needs no
	// passphrase, so it works unattended. Fall back to the passphrase
	// prompt when the token-based unlock is unavailable (older systemd) or
	// the operator asked for it.
	method := repairUnlockPassphrase
	switch {
	case c.RepairUnlock != "":
		method = repairUnlockPassphrase // explicit selection, handled in repairUnlockArgs
	case c.NonInteractive:
		method = repairUnlockTPM2Token
	}

	runRepair := func(m repairUnlockMethod) error {
		args := []string{
			"--wipe-slot=tpm2",
			"--tpm2-device=auto",
			"--tpm2-pcrlock=" + c.PolicyOutput,
		}
		unlockArgs, err := c.repairUnlockArgs(m)
		if err != nil {
			return err
		}
		args = append(args, unlockArgs...)
		args = append(args, c.LUKSDevice)

		fmt.Printf("  Running: systemd-cryptenroll %s\n", strings.Join(args, " "))
		fmt.Println()
		return repairRunner(cryptenroll, args)
	}

	switch method {
	case repairUnlockTPM2Token:
		fmt.Println("  Unlocking the volume with the existing TPM2 token (no passphrase).")
	default:
		fmt.Println("  Unlocking the volume — you will be prompted for the disk passphrase.")
		fmt.Println("  (use --non-interactive to unlock via the existing TPM2 token instead)")
	}

	// confirmRepaired verifies that the re-seal took effect. A failed
	// re-read means the state is unknown — report it instead of claiming
	// success. Used after every successful attempt, including the retry.
	confirmRepaired := func() error {
		token, tokErr := getLUKSTPMToken(c.LUKSDevice)
		if tokErr != nil {
			return fmt.Errorf("--repair-token: re-seal ran but the token could not be re-read: %w", tokErr)
		}
		newPolicy, policyErr := pcrlock.ParsePolicy(c.PolicyOutput)
		if policyErr != nil {
			return fmt.Errorf("--repair-token: re-seal ran but the policy could not be parsed: %w", policyErr)
		}
		status, note, _ := tokenNVStatus(token, newPolicy)
		if status != "match" {
			// "Not stale" is not sufficient proof: a classic PCR-bound
			// token has no pcrlock binding at all, and an undecidable
			// token is not verified either. Only an actual pcrlock-bound
			// match confirms the repair.
			fmt.Println()
			fmt.Printf("  %s Token does not match the policy after the re-seal (%s)\n", errStyle.Render("✗"), status)
			return fmt.Errorf("--repair-token: token state after the re-seal is %q, want a pcrlock-bound match (%s)", status, note)
		}
		fmt.Println()
		fmt.Printf("  %s Token re-sealed — it matches the policy again\n", okStyle.Render("✓"))
		return nil
	}

	// afterRepaired confirms the repair and then refreshes the PCR 11
	// prediction: cryptenroll rewrites the LUKS2 JSON metadata, so the
	// header digest — and with it the PCR 11 the next boot produces —
	// changes. The prediction injected before the repair would otherwise be
	// stale, and the repaired token would still fail to unseal.
	afterRepaired := func() error {
		if err := confirmRepaired(); err != nil {
			return err
		}
		if !c.luksHeaderEnabled {
			return nil
		}
		if err := injectHeaderPrediction(c.PolicyOutput, c.LUKSDevice); err != nil {
			return fmt.Errorf("the token was re-sealed but the LUKS header prediction could not be refreshed: %w", err)
		}
		return nil
	}

	repairErr := runRepair(method)
	if repairErr == nil {
		return afterRepaired()
	}

	// The repair failed. The unattended case cannot succeed: the very
	// situation the relock service exists for (a firmware update changed
	// PCR 7) means the OLD token can no longer unlock the volume. Asking
	// for a passphrase without a terminal would hang the service, so the
	// operator is told what to run instead.
	if !stdinIsTerminal() {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  %s Token re-seal failed: %v\n", errStyle.Render("✗"), repairErr)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, manualRepairMessage(c.LUKSDevice, c.UKIPath, c.PolicyOutput))
		fmt.Fprintln(os.Stderr)
		// The policy was regenerated successfully — failing the whole
		// command here would skip the relock service's ExecStartPost
		// (recovery --auto-reseed) and leave the recovery seed stale
		// as well. Report and continue instead.
		return nil
	}

	// Interactive: the passphrase prompt already ran in the first
	// attempt, so retrying it identically would only repeat the same
	// failure. Only a token-based unlock is worth a second try.
	if method == repairUnlockPassphrase && c.RepairUnlock == "" {
		fmt.Println()
		fmt.Printf("  %s Re-seal failed: %v\n", errStyle.Render("✗"), repairErr)
		fmt.Println()
		fmt.Println("  The passphrase unlock did not succeed. Try the TPM-token unlock:")
		fmt.Println("    sudo vanguard update -u " + c.UKIPath + " -l " + c.LUKSDevice + " --repair-token --non-interactive")
		return fmt.Errorf("--repair-token: systemd-cryptenroll failed: %w", repairErr)
	}

	fmt.Println()
	fmt.Printf("  %s Re-seal failed (%v) — retrying with the TPM2 token.\n", warnStyle.Render("⚠"), repairErr)
	if retryErr := runRepair(repairUnlockTPM2Token); retryErr != nil {
		return fmt.Errorf("--repair-token: systemd-cryptenroll failed: %w (TPM-token retry also failed: %v)", repairErr, retryErr)
	}
	return afterRepaired()
}

func box(title string, lines []string) string {
	content := strings.Join(lines, "\n")
	if title != "" {
		content = headerSty.Render(title) + "\n" + content
	}
	return "\n" + boxStyle.Render(content) + "\n"
}

func pcrName(p int) string {
	names := map[int]string{
		2:  "external-code",
		3:  "external-config",
		4:  "boot-loader-code",
		5:  "GPT-partition",
		7:  "secure-boot-policy",
		11: "LUKS-header",
	}
	n, ok := names[p]
	if !ok {
		return "unknown"
	}
	return n
}

func getParentDisk(devicePath string) string {
	realPath, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		realPath = devicePath
	}
	devName := filepath.Base(realPath)
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		diskName := entry.Name()
		partPath := filepath.Join("/sys/block", diskName, devName)
		if _, err := os.Stat(partPath); err == nil {
			return "/dev/" + diskName
		}
	}
	return ""
}
