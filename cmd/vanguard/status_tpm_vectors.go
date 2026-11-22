package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/zaolin/vanguard/internal/tpm"
)

// buildTPMVulnerabilityVector reports known TPM vendor/firmware
// vulnerabilities based on the TPM's own identity, plus the BIOS/AGESA
// identification where DMI provides it.
func buildTPMVulnerabilityVector(data *statusData) threatVector {
	v := threatVector{Name: "TPM Vulnerabilities (vendor/firmware)"}

	if !data.TPM.Present {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM 2.0",
			Status: "critical",
			Detail: "not available",
		})
		return v
	}

	if data.TPM.Identity == nil {
		detail := "could not be read"
		if data.TPM.IdentityError != "" {
			detail += ": " + data.TPM.IdentityError
		}
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM identity",
			Status: "info",
			Detail: detail,
		})
		return v
	}

	id := data.TPM.Identity
	v.Mitigations = append(v.Mitigations, mitigation{
		Name:   "TPM vendor",
		Status: "info",
		Detail: fmt.Sprintf("%s (vendor %q), firmware %s", id.Manufacturer, id.VendorString, id.Firmware),
	})
	if id.FirmwareTPM {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM type",
			Status: "info",
			Detail: "firmware TPM on the host CPU — no discrete bus to tap",
		})
	}

	// ROCA severity depends on whether ANY enrolled primary is RSA — the
	// enumeration order of the LUKS devices must not change the verdict.
	primaryAlg := "ecc"
	for _, d := range data.LUKSDevices {
		if d.Token != nil && d.Token.PrimaryAlg == "rsa" {
			primaryAlg = "rsa"
			break
		}
	}
	for _, adv := range evaluateTPMAdvisories(tpm.TPMFamily(id.Family), id.VendorString, primaryAlg) {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   adv.Name,
			Status: adv.Status,
			Detail: adv.Detail,
			Fix:    adv.Fix,
		})
	}

	if b := readBIOSInfo(); b.String() != "unknown" {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "BIOS / AGESA",
			Status: "info",
			Detail: b.String() + " — DMI version; the AGESA patch level cannot be verified automatically",
		})
	}

	return v
}

// buildTPMHealthVector reports whether the TPM actually works for vanguard:
// PCR banks, RNG, and a real seal/unseal roundtrip. When a pcrlock policy
// exists, the NV index contents are compared against the policy prediction.
func buildTPMHealthVector(data *statusData) threatVector {
	v := threatVector{Name: "TPM Functional Health"}

	if !data.TPM.Present {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM 2.0",
			Status: "critical",
			Detail: "not available",
		})
		return v
	}

	switch {
	case data.TPM.BanksError != "":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCR banks",
			Status: "warning",
			Detail: "could not be read: " + data.TPM.BanksError,
		})
	case len(data.TPM.Banks) == 0:
		// No data at all: the bank state is unknown, not broken. Reporting
		// "no SHA-256" here would be a false critical.
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCR banks",
			Status: "info",
			Detail: "no bank information returned",
		})
	case !hasSHA256Bank(data.TPM.Banks):
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCR banks",
			Status: "critical",
			Detail: fmt.Sprintf("no SHA-256 bank (%s) — pcrlock cannot work", strings.Join(data.TPM.Banks, ", ")),
			Fix:    "Enable the SHA-256 PCR bank in the firmware",
		})
	default:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCR banks",
			Status: "ok",
			Detail: strings.Join(data.TPM.Banks, ", "),
		})
	}

	switch {
	case data.TPM.RandomOK != nil && *data.TPM.RandomOK:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "RNG",
			Status: "ok",
			Detail: "consecutive GetRandom calls differ",
		})
	case data.TPM.RandomOK != nil:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "RNG",
			Status: "critical",
			Detail: "consecutive GetRandom calls returned identical output — the RNG may be broken",
		})
	case data.TPM.RandomError != "":
		// The check could not run: report that, not a broken RNG.
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "RNG",
			Status: "warning",
			Detail: "could not be verified: " + data.TPM.RandomError,
		})
	}

	switch {
	case data.TPM.RoundtripSkipped != "":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Seal/unseal roundtrip",
			Status: "info",
			Detail: "not attempted — " + data.TPM.RoundtripSkipped,
		})
	case data.TPM.RoundtripOK != nil && *data.TPM.RoundtripOK:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Seal/unseal roundtrip",
			Status: "ok",
			Detail: "SRK create → seal → unseal verified",
		})
	case data.TPM.RoundtripOK != nil && data.TPM.RoundtripClass == "unverified":
		// Authorization or transport problem: the check could not run.
		// That is not proof that the TPM cannot protect the key.
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Seal/unseal roundtrip",
			Status: "warning",
			Detail: "could not be verified: " + data.TPM.RoundtripError,
			Fix:    "If owner/lockout auth is set, run the check with the required authorization",
		})
	case data.TPM.RoundtripOK != nil:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Seal/unseal roundtrip",
			Status: "critical",
			Detail: data.TPM.RoundtripError,
			Fix:    "The TPM cannot protect the disk key — check the firmware and TPM state",
		})
	}

	// All-zero PCRs would mean the boot chain was never measured: the
	// pcrlock binding is then meaningless, regardless of the digest check.
	if data.PCRLock != nil && pcrsAllZero(data.PCRLock.PCRResults) {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCR measurements",
			Status: "warning",
			Detail: "all PCR values are zero — the boot chain was not measured, so the pcrlock binding is meaningless",
			Fix:    "Check the firmware's TPM event log: the boot chain is not being measured",
		})
	}

	if data.PCRLock != nil && data.PCRLock.PolicyPath != "" {
		if data.TPM.AuthBlocked != "" {
			// Same rule as the roundtrip: no new authorizations with an
			// empty auth value when the lockout state is unknown, the TPM
			// is locked out, or owner/lockout auth is set.
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "NV contents vs policy",
				Status: "info",
				Detail: "not verified — " + data.TPM.AuthBlocked,
			})
		} else if m, ok := nvPolicyMitigation(data.PCRLock.PolicyPath); ok {
			v.Mitigations = append(v.Mitigations, m)
		}
	}

	return v
}

// hasSHA256Bank reports whether the TPM exposes the bank pcrlock needs.
func hasSHA256Bank(banks []string) bool {
	for _, b := range banks {
		if b == "sha256" {
			return true
		}
	}
	return false
}

// nvPolicyMitigation compares the pcrlock NV index contents with the digest
// computed from the policy predictions.
func nvPolicyMitigation(policyPath string) (mitigation, bool) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return mitigation{}, false
	}
	policy, err := tpm.ParsePCRLockJSON(data)
	if err != nil || policy.NVIndex == 0 {
		return mitigation{}, false
	}

	match, err := tpm.New().CheckNVPolicyDigest(policy.NVIndex, policy.Bank, policy.PCRPredictions)
	if err != nil {
		return mitigation{
			Name:   "NV contents vs policy",
			Status: "info",
			Detail: fmt.Sprintf("could not be verified (0x%x): %v", policy.NVIndex, err),
		}, true
	}
	if !match {
		return mitigation{
			Name:   "NV contents vs policy",
			Status: "critical",
			Detail: fmt.Sprintf("NV index 0x%x does not hold the predicted policy digest — it was rewritten or redefined", policy.NVIndex),
			Fix:    "Re-run vanguard update and re-enroll the token with --repair-token",
		}, true
	}
	return mitigation{
		Name:   "NV contents vs policy",
		Status: "ok",
		Detail: fmt.Sprintf("NV index 0x%x holds the predicted policy digest", policy.NVIndex),
	}, true
}

// buildBootParamVector reports boot parameters that weaken or bypass the TPM
// unlock (test hooks, embedded PINs, rescue shells).
func buildBootParamVector(data *statusData) threatVector {
	v := threatVector{Name: "Boot Parameter Bypass"}

	text, err := cmdlineReader()
	if err != nil {
		// An unreadable command line is not a clean one: say so instead of
		// claiming no bypasses were found.
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Kernel command line",
			Status: "info",
			Detail: "could not be read: " + err.Error(),
		})
		return v
	}

	findings := auditKernelCmdline(text)
	if len(findings) == 0 {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Kernel command line",
			Status: "ok",
			Detail: "no bypass or test parameters found",
		})
		return v
	}

	v.Mitigations = append(v.Mitigations, findings...)
	return v
}
