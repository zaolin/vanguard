package main

import (
	"fmt"
	"strings"

	"github.com/zaolin/vanguard/internal/tpm"
)

// tpmAdvisory is one known TPM vulnerability relevant to this machine.
type tpmAdvisory struct {
	ID     string
	Name   string
	Status string // "ok", "info", "warning", "critical"
	Detail string
	Fix    string
}

// evaluateTPMAdvisories maps a TPM family to known vulnerability advisories.
//
// The table is curated offline: no network access and deterministic output for
// a given family. It deliberately reports only advisories that apply — a clean
// vendor must not produce noise.
//
// primaryAlg influences ROCA: an RSA primary makes it critical, anything else
// keeps it informational. vendorString is only used for the simulator message.
func evaluateTPMAdvisories(family tpm.TPMFamily, vendorString, primaryAlg string) []tpmAdvisory {
	var out []tpmAdvisory

	switch family {
	case tpm.TPMFamilyInfineon:
		// ROCA / CVE-2017-15361: the RSALib on Infineon TPMs generates
		// factorable RSA keys. vanguard uses ECC, so this is informational
		// unless an RSA primary was actually enrolled.
		if primaryAlg == "rsa" {
			out = append(out, tpmAdvisory{
				ID:     "roca",
				Name:   "ROCA (CVE-2017-15361)",
				Status: "critical",
				Detail: "Infineon TPM: RSA keys generated on this TPM are factorable, and an RSA primary is enrolled",
				Fix:    "Update the TPM/BIOS firmware and re-enroll with an ECC primary (vanguard default)",
			})
		} else {
			out = append(out, tpmAdvisory{
				ID:     "roca",
				Name:   "ROCA (CVE-2017-15361)",
				Status: "advisory",
				Detail: "Infineon TPM: ROCA affects RSA keys generated on the TPM; the enrolled primary is not RSA",
				Fix:    "Keep the ECC primary; update the firmware when a fix is available for your model",
			})
		}

	case tpm.TPMFamilyIntel:
		out = append(out, tpmAdvisory{
			ID:     "tpm-fail",
			Name:   "TPM-Fail timing side channel (CVE-2019-11090, CVE-2019-16863)",
			Status: "advisory",
			Detail: "Intel PTT (firmware TPM): ECDSA signing on affected firmware leaks key material through timing",
			Fix:    "Update the BIOS/firmware to a release that includes the Intel PTT fix for your CPU generation",
		})

	case tpm.TPMFamilyST:
		out = append(out, tpmAdvisory{
			ID:     "tpm-fail",
			Name:   "TPM-Fail timing side channel (CVE-2019-11090, CVE-2019-16863)",
			Status: "advisory",
			Detail: "STMicroelectronics TPM: affected firmware leaks key material through ECDSA timing",
			Fix:    "Update the TPM firmware to the vendor's patched release",
		})

	case tpm.TPMFamilyAMD:
		out = append(out, tpmAdvisory{
			ID:     "faultpm",
			Name:   "faulTPM (AMD fTPM fault injection, 2023)",
			Status: "advisory",
			Detail: "AMD fTPM: fault-injection attacks can extract sealed keys on unpatched firmware; the AGESA patch level cannot be verified automatically",
			Fix:    "Update the BIOS/AGESA to the latest release for your board and check the AMD faulTPM advisory",
		})

	case tpm.TPMFamilySimulator:
		out = append(out, tpmAdvisory{
			ID:     "simulator",
			Name:   "TPM simulator",
			Status: "info",
			Detail: fmt.Sprintf("TPM reports vendor %q — sealed keys are NOT protected by real hardware", vendorString),
			Fix:    "Use a hardware TPM for any protection beyond obfuscation",
		})
	}

	return out
}

// biosInfo describes the firmware the machine booted from, as reported by
// DMI/SMBIOS. This is the BIOS version, not necessarily the AGESA build.
type biosInfo struct {
	Vendor  string
	Version string
	Date    string
	Board   string
}

// String renders the BIOS identification for the status output.
func (b biosInfo) String() string {
	parts := []string{}
	if b.Vendor != "" {
		parts = append(parts, b.Vendor)
	}
	if b.Version != "" {
		parts = append(parts, b.Version)
	}
	if b.Date != "" {
		parts = append(parts, "("+b.Date+")")
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " ")
}
