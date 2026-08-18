package main

import (
	"fmt"
	"os"
	"path/filepath"
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
		// Case-insensitive .efi stripping — handles kernel.efi, kernel.EFI, BOOTX64.EFI
		ukiBase := c.UKIPath
		if strings.HasSuffix(strings.ToLower(ukiBase), ".efi") {
			ukiBase = ukiBase[:len(ukiBase)-4]
		}
		c.PolicyOutput = ukiBase + ".pcrlock.json"
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

	luksHeaderEnabled := c.LUKSDevice != "" && !c.NoLUKSHeader

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
	if err := pcrlock.MakePolicy(c.PolicyOutput); err != nil {
		return fmt.Errorf("failed to generate policy: %w", err)
	}

	// Inject the NEW LUKS header prediction into the policy.
	// make-policy generates the policy using the event log (which has the
	// OLD LUKS header hash from the last boot). But the NEXT boot will use
	// the NEW hash (because vanguard update just re-enrolled the TPM2 token,
	// changing the LUKS2 JSON metadata). InjectLUKSHeaderPrediction adds
	// the NEW predicted PCR 11 value so the next boot's unseal succeeds.
	if luksHeaderEnabled {
		if err := pcrlock.InjectLUKSHeaderPrediction(c.PolicyOutput, c.LUKSDevice); err != nil {
			if c.Verbose {
				fmt.Printf("Note: failed to inject LUKS header prediction: %v\n", err)
			}
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
				gptEnabled = false
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

	if c.LUKSDevice != "" {
		token, err := pcrlock.GetLUKSTPMToken(c.LUKSDevice)
		if err != nil {
			summaryLines = append(summaryLines, warnStyle.Render(fmt.Sprintf("Token:        not found on %s", c.LUKSDevice)))
		} else {
			if token.NVIndex == policyNVIndex {
				summaryLines = append(summaryLines, fmt.Sprintf("Token:        %s (NV matches)", okStyle.Render("OK")))
			} else {
				summaryLines = append(summaryLines, errStyle.Render(fmt.Sprintf("Token NV mismatch! Policy=0x%x, Token=0x%x", policyNVIndex, token.NVIndex)))
				summaryLines = append(summaryLines, "")
				summaryLines = append(summaryLines, dimStyle.Render("Re-enroll token:"))
				summaryLines = append(summaryLines, dimStyle.Render(fmt.Sprintf(" systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto")))
				summaryLines = append(summaryLines, dimStyle.Render(fmt.Sprintf("   --tpm2-with-pin=yes --tpm2-pcrlock=%s %s", c.PolicyOutput, c.LUKSDevice)))
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
			pcrFailures := 0
			for p, match := range pcrMatches {
				if !match {
					pcrFailures++
					integrityLines = append(integrityLines, errStyle.Render(fmt.Sprintf("✗ PCR %d mismatch (current: %s)", p, currentValues[p])))
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
