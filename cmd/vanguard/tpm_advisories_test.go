package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zaolin/vanguard/internal/tpm"
)

// TestEvaluateTPMAdvisories pins the advisory mapping per vendor and the
// algorithm-dependent ROCA severity.
func TestEvaluateTPMAdvisories(t *testing.T) {
	tests := []struct {
		name       string
		family     tpm.TPMFamily
		primaryAlg string
		wantID     string
		wantStatus string
		wantEmpty  bool
	}{
		{name: "Infineon with RSA primary is critical", family: tpm.TPMFamilyInfineon, primaryAlg: "rsa", wantID: "roca", wantStatus: "critical"},
		{name: "Infineon with ECC primary is informational", family: tpm.TPMFamilyInfineon, primaryAlg: "ecc", wantID: "roca", wantStatus: "advisory"},
		{name: "Intel PTT is a TPM-Fail warning", family: tpm.TPMFamilyIntel, primaryAlg: "ecc", wantID: "tpm-fail", wantStatus: "advisory"},
		{name: "ST is a TPM-Fail warning", family: tpm.TPMFamilyST, primaryAlg: "ecc", wantID: "tpm-fail", wantStatus: "advisory"},
		{name: "AMD fTPM is a faulTPM warning", family: tpm.TPMFamilyAMD, primaryAlg: "ecc", wantID: "faultpm", wantStatus: "advisory"},
		{name: "a simulator is informational", family: tpm.TPMFamilySimulator, primaryAlg: "ecc", wantID: "simulator", wantStatus: "info"},
		{name: "Nuvoton has no advisory", family: tpm.TPMFamilyNuvoton, primaryAlg: "ecc", wantEmpty: true},
		{name: "an unknown vendor has no advisory", family: tpm.TPMFamilyUnknown, primaryAlg: "ecc", wantEmpty: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateTPMAdvisories(tc.family, "vendor", tc.primaryAlg)
			if tc.wantEmpty {
				if len(got) != 0 {
					t.Errorf("expected no advisories, got %v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected exactly one advisory, got %v", got)
			}
			if got[0].ID != tc.wantID {
				t.Errorf("advisory ID = %q, want %q", got[0].ID, tc.wantID)
			}
			if got[0].Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", got[0].Status, tc.wantStatus)
			}
			if got[0].Detail == "" || got[0].Fix == "" {
				t.Error("an advisory must carry a detail and a fix hint")
			}
		})
	}
}

// TestAuditKernelCmdline pins every bypass/test pattern the audit must catch,
// and that a clean command line stays silent.
func TestAuditKernelCmdline(t *testing.T) {
	tests := []struct {
		name       string
		cmdline    string
		wantStatus string
		wantName   string
		wantClean  bool
	}{
		{name: "embedded PIN", cmdline: "quiet vanguard.testpin=1234", wantName: "vanguard.testpin", wantStatus: "critical"},
		{name: "test mode", cmdline: "vanguard.testmode=1", wantName: "vanguard.testmode", wantStatus: "critical"},
		{name: "HOTP test hook alone is inert", cmdline: "vanguard.testhotp=1", wantName: "vanguard.testhotp", wantStatus: "info"},
		{name: "test mode disabled is clean", cmdline: "vanguard.testmode=0", wantClean: true},
		{name: "shell init", cmdline: "quiet init=/bin/sh", wantName: "init", wantStatus: "critical"},
		{name: "bash rdinit", cmdline: "rdinit=/bin/bash", wantName: "rdinit", wantStatus: "critical"},
		{name: "single user mode", cmdline: "single", wantName: "single", wantStatus: "critical"},
		{name: "rd break", cmdline: "rd.break", wantName: "rd.break", wantStatus: "critical"},
		{name: "vanguard debug", cmdline: "vanguard.debug=1", wantName: "vanguard.debug", wantStatus: "info"},
		{name: "kernel debug", cmdline: "debug", wantName: "debug", wantStatus: "info"},
		{name: "normal boot is clean", cmdline: "quiet splash root=/dev/mapper/gentoo-root ro", wantClean: true},
		{name: "an unrelated init path is clean", cmdline: "init=/sbin/init", wantClean: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := auditKernelCmdline(tc.cmdline)
			if tc.wantClean {
				if len(got) != 0 {
					t.Errorf("expected no findings, got %v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected one finding, got %v", got)
			}
			if got[0].Name != tc.wantName {
				t.Errorf("name = %q, want %q", got[0].Name, tc.wantName)
			}
			if got[0].Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", got[0].Status, tc.wantStatus)
			}
		})
	}
}

// TestBootParamVectorClean verifies the vector reports OK when the command
// line has no bypasses.
func TestBootParamVectorClean(t *testing.T) {
	orig := cmdlineReader
	t.Cleanup(func() { cmdlineReader = orig })
	cmdlineReader = func() (string, error) { return "quiet splash", nil }

	v := buildBootParamVector(&statusData{})
	if len(v.Mitigations) != 1 || v.Mitigations[0].Status != "ok" {
		t.Errorf("expected a single OK mitigation, got %v", v.Mitigations)
	}
}

// TestBootParamVectorCritical verifies the vector surfaces a critical finding.
func TestBootParamVectorCritical(t *testing.T) {
	orig := cmdlineReader
	t.Cleanup(func() { cmdlineReader = orig })
	cmdlineReader = func() (string, error) { return "quiet vanguard.testpin=1234", nil }

	v := buildBootParamVector(&statusData{})
	if len(v.Mitigations) != 1 || v.Mitigations[0].Status != "critical" {
		t.Errorf("expected a critical mitigation, got %v", v.Mitigations)
	}
}

// TestVulnerabilityVectorIncludesAdvisory verifies the vector carries the
// vendor's advisory and the BIOS line.
func TestVulnerabilityVectorIncludesAdvisory(t *testing.T) {
	origDMI := dmiRoot
	t.Cleanup(func() { dmiRoot = origDMI })
	dir := t.TempDir()
	dmiRoot = dir
	for name, content := range map[string]string{
		"bios_vendor":  "ACME",
		"bios_version": "1.2.3",
		"bios_date":    "01/01/2026",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	data := &statusData{}
	data.TPM.Present = true
	data.TPM.Identity = &tpmIdentityInfo{
		Manufacturer: "INTC",
		VendorString: "INTEL",
		Firmware:     "1.2",
		Family:       string(tpm.TPMFamilyIntel),
		FirmwareTPM:  true,
	}

	v := buildTPMVulnerabilityVector(data)

	var foundAdvisory, foundBIOS bool
	for _, m := range v.Mitigations {
		if strings.Contains(m.Name, "TPM-Fail") {
			foundAdvisory = true
			if m.Status != "advisory" {
				t.Errorf("TPM-Fail status = %q, want advisory", m.Status)
			}
		}
		if m.Name == "BIOS / AGESA" {
			foundBIOS = true
			if !strings.Contains(m.Detail, "ACME 1.2.3") {
				t.Errorf("BIOS detail = %q, want the DMI identification", m.Detail)
			}
		}
	}
	if !foundAdvisory {
		t.Errorf("no TPM-Fail mitigation in %v", v.Mitigations)
	}
	if !foundBIOS {
		t.Errorf("no BIOS / AGESA mitigation in %v", v.Mitigations)
	}
}

// TestVulnerabilityVectorRSAAnywhere pins that an RSA primary on ANY device
// escalates ROCA, regardless of the device enumeration order.
func TestVulnerabilityVectorRSAAnywhere(t *testing.T) {
	data := &statusData{}
	data.TPM.Present = true
	data.TPM.Identity = &tpmIdentityInfo{
		Manufacturer: "IFX ",
		Family:       string(tpm.TPMFamilyInfineon),
	}
	data.LUKSDevices = []luksDeviceInfo{
		{Token: &tokenDetail{PrimaryAlg: "ecc"}},
		{Token: &tokenDetail{PrimaryAlg: "rsa"}},
		{Token: &tokenDetail{PrimaryAlg: "ecc"}},
	}

	v := buildTPMVulnerabilityVector(data)

	found := false
	for _, m := range v.Mitigations {
		if strings.Contains(m.Name, "ROCA") {
			found = true
			if m.Status != "critical" {
				t.Errorf("ROCA status = %q with an RSA primary present, want critical", m.Status)
			}
		}
	}
	if !found {
		t.Error("no ROCA mitigation")
	}
}

// TestHealthVectorEmptyDataIsNotCritical pins that missing data is reported
// as unknown, never as a false "critical" finding.
func TestHealthVectorEmptyDataIsNotCritical(t *testing.T) {
	data := &statusData{}
	data.TPM.Present = true

	v := buildTPMHealthVector(data)
	for _, m := range v.Mitigations {
		if m.Status == "critical" {
			t.Errorf("unexpected critical mitigation with no data: %+v", m)
		}
	}
}

// TestHealthVectorRequiresSHA256 verifies that a missing SHA-256 bank is
// reported as critical rather than as a later unseal failure.
func TestHealthVectorRequiresSHA256(t *testing.T) {
	data := &statusData{}
	data.TPM.Present = true
	data.TPM.Banks = []string{"sha1"}

	v := buildTPMHealthVector(data)

	found := false
	for _, m := range v.Mitigations {
		if m.Name == "PCR banks" {
			found = true
			if m.Status != "critical" {
				t.Errorf("PCR banks status = %q, want critical", m.Status)
			}
		}
	}
	if !found {
		t.Error("no PCR banks mitigation")
	}
}

// TestHealthVectorRoundtripResult verifies that the roundtrip outcome is
// surfaced with its error detail.
func TestHealthVectorRoundtripResult(t *testing.T) {
	data := &statusData{}
	data.TPM.Present = true
	data.TPM.Banks = []string{"sha256"}
	data.TPM.RoundtripOK = boolPtr(false)
	data.TPM.RoundtripError = "unseal: TPM_RC_FAILURE"

	v := buildTPMHealthVector(data)

	found := false
	for _, m := range v.Mitigations {
		if m.Name == "Seal/unseal roundtrip" {
			found = true
			if m.Status != "critical" {
				t.Errorf("roundtrip status = %q, want critical", m.Status)
			}
			if !strings.Contains(m.Detail, "TPM_RC_FAILURE") {
				t.Errorf("the error detail is missing: %q", m.Detail)
			}
		}
	}
	if !found {
		t.Error("no roundtrip mitigation")
	}
}
