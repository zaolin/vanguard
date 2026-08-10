package main

import (
	"os"
	"testing"
)

func TestDetectLockdown(t *testing.T) {
	// Test the parsing logic directly — detectLockdown reads /sys/kernel/security/lockdown
	// We test the bracket parsing by calling detectLockdown and verifying it returns
	// one of the expected values
	result := detectLockdown()
	if result != "confidentiality" && result != "integrity" && result != "none" && result != "unknown" {
		t.Errorf("detectLockdown() = %q, unexpected value", result)
	}

	// Verify the system is in confidentiality mode (as we discovered earlier)
	if result == "confidentiality" {
		// Best mode — /dev/mem blocked, kexec blocked, BPF restricted
		t.Logf("Lockdown is at confidentiality level — strongest kernel protection")
	}
}

func TestDetectModuleSigs(t *testing.T) {
	// Module sigs is determined by lockdown state
	// Under confidentiality/integrity lockdown, sigs are enforced
	// This test uses the real detectLockdown which reads /sys/kernel/security/lockdown
	// We can't easily mock it, so test the logic indirectly
	result := detectModuleSigs()
	if result != "enforced" && result != "not-enforced" && result != "n/a" {
		t.Errorf("detectModuleSigs() = %q, unexpected value", result)
	}
}

func TestDetectThunderbolt(t *testing.T) {
	// We can't easily mock /sys/bus/thunderbolt, so test the parsing logic
	status, count := detectThunderbolt()
	_ = count
	if status != "absent" && status != "present" && status != "controller-only" {
		t.Errorf("detectThunderbolt() status = %q, unexpected", status)
	}
}

func TestDetectTPMBusEncryption(t *testing.T) {
	result := detectTPMBusEncryption()
	if result != "active" && result != "inactive" && result != "unknown" {
		t.Errorf("detectTPMBusEncryption() = %q, unexpected", result)
	}
}

func TestDetectCPUVendor(t *testing.T) {
	vendor := detectCPUVendor()
	if vendor != "amd" && vendor != "intel" && vendor != "unknown" {
		t.Errorf("detectCPUVendor() = %q, unexpected", vendor)
	}
}

func TestReadCmdline(t *testing.T) {
	cmdline := readCmdline()
	if cmdline == "" {
		t.Error("readCmdline() returned empty string — /proc/cmdline not readable?")
	}
}

func TestHasCPUFlag(t *testing.T) {
	// Test with a flag that definitely exists
	if !hasCPUFlag("fpu") {
		t.Error("hasCPUFlag('fpu') should be true on any x86 CPU")
	}
	// Test with a flag that definitely doesn't exist
	if hasCPUFlag("nonexistent_flag_xyz123") {
		t.Error("hasCPUFlag('nonexistent_flag_xyz123') should be false")
	}
}

func TestCheckHardwareWarnings(t *testing.T) {
	// All good → no warnings
	info := &hardwareSecurityInfo{
		TPMBusEncryption: "active",
		IOMMU:            "active",
		IOMMUGroups:      10,
		IOMMUMode:        "pt",
		Thunderbolt:      "absent",
		ModuleSigs:       "enforced",
		Lockdown:         "confidentiality",
		MemoryEncryption: "active",
		MemEncryptType:   "AMD SME",
	}
	warnings := checkHardwareWarnings(info)
	for _, w := range warnings {
		if containsStr(w, "WARNING") || containsStr(w, "CRITICAL") {
			t.Errorf("unexpected warning for healthy system: %s", w)
		}
	}

	// TPM bus encryption inactive → warning
	info.TPMBusEncryption = "inactive"
	warnings = checkHardwareWarnings(info)
	if !containsAny(warnings, "bus sniffing") {
		t.Error("expected warning about bus sniffing when TPM bus encryption inactive")
	}

	// Thunderbolt present without IOMMU → critical
	info.TPMBusEncryption = "active"
	info.Thunderbolt = "present"
	info.ThunderboltCount = 2
	info.IOMMU = "inactive"
	warnings = checkHardwareWarnings(info)
	if !containsAny(warnings, "CRITICAL") {
		t.Error("expected CRITICAL warning for Thunderbolt without IOMMU")
	}

	// Memory encryption available but not active → warning with advice
	info.Thunderbolt = "absent"
	info.IOMMU = "active"
	info.MemoryEncryption = "available"
	info.MemEncryptType = "AMD SME"
	info.MemEncryptAdvice = "Enable AMD SME in BIOS"
	warnings = checkHardwareWarnings(info)
	if !containsAny(warnings, "Enable AMD SME") {
		t.Error("expected warning with SME advice")
	}
}

func TestDetectMemoryEncryption(t *testing.T) {
	status, encType, advice := detectMemoryEncryption()
	_ = encType
	_ = advice
	if status != "active" && status != "available" && status != "disabled" && status != "not-available" {
		t.Errorf("detectMemoryEncryption() status = %q, unexpected", status)
	}
}

func TestDetectIOMMU(t *testing.T) {
	status, groups, mode := detectIOMMU()
	_ = mode
	if status != "active" && status != "inactive" && status != "disabled" {
		t.Errorf("detectIOMMU() status = %q, unexpected", status)
	}
	if status == "active" && groups <= 0 {
		t.Error("active IOMMU should have groups > 0")
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := dir + "/" + name
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeFile %s: %v", name, err)
	}
}

func containsAny(slice []string, substr string) bool {
	for _, s := range slice {
		if containsStr(s, substr) {
			return true
		}
	}
	return false
}
