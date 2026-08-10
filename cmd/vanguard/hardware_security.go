package main

import (
	"os"
	"path/filepath"
	"strings"
)

// hardwareSecurityInfo contains hardware-level security feature status.
type hardwareSecurityInfo struct {
	TPMBusEncryption string   `json:"tpmBusEncryption"`
	IOMMU            string   `json:"iommu"`
	IOMMUGroups      int      `json:"iommuGroups,omitempty"`
	IOMMUMode        string   `json:"iommuMode,omitempty"`
	Thunderbolt      string   `json:"thunderbolt"`
	ThunderboltCount int      `json:"thunderboltCount,omitempty"`
	ModuleSigs       string   `json:"moduleSignatures"`
	Lockdown         string   `json:"lockdown"`
	MemoryEncryption string   `json:"memoryEncryption"`
	MemEncryptType   string   `json:"memEncryptType,omitempty"`
	MemEncryptAdvice string   `json:"memEncryptAdvice,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// collectHardwareSecurityStatus reads sysfs/procfs to determine hardware
// security feature status.
func collectHardwareSecurityStatus() *hardwareSecurityInfo {
	info := &hardwareSecurityInfo{}

	// 1. TPM Bus Encryption (CONFIG_TCG_TPM2_HMAC)
	info.TPMBusEncryption = detectTPMBusEncryption()

	// 2. IOMMU / DMA Protection
	info.IOMMU, info.IOMMUGroups, info.IOMMUMode = detectIOMMU()

	// 3. Thunderbolt
	info.Thunderbolt, info.ThunderboltCount = detectThunderbolt()

	// 4. Module Signatures
	info.ModuleSigs = detectModuleSigs()

	// 5. Kernel Lockdown
	info.Lockdown = detectLockdown()

	// 6. Memory Encryption (AMD SME / Intel TME / AMD TSME)
	info.MemoryEncryption, info.MemEncryptType, info.MemEncryptAdvice = detectMemoryEncryption()

	// Generate warnings
	info.Warnings = checkHardwareWarnings(info)

	return info
}

// detectTPMBusEncryption checks if the kernel is using HMAC sessions with
// parameter encryption for TPM transactions (CONFIG_TCG_TPM2_HMAC).
// When active, all TPM commands through /dev/tpmrm0 use encrypted parameters,
// protecting against bus sniffing attacks.
func detectTPMBusEncryption() string {
	// The null_name sysfs file is populated when CONFIG_TCG_TPM2_HMAC is enabled.
	// It contains the name of the null primary key used for HMAC session establishment.
	data, err := os.ReadFile("/sys/class/tpm/tpm0/null_name")
	if err != nil {
		return "unknown"
	}
	if len(strings.TrimSpace(string(data))) > 0 {
		return "active"
	}
	return "inactive"
}

// detectIOMMU checks for IOMMU presence and enforcement mode.
// Returns status string, number of IOMMU groups, and mode from cmdline.
func detectIOMMU() (status string, groups int, mode string) {
	// Check for IOMMU groups
	entries, err := os.ReadDir("/sys/kernel/iommu_groups/")
	if err != nil {
		return "inactive", 0, ""
	}
	groups = len(entries)
	if groups == 0 {
		return "inactive", 0, ""
	}

	// Check cmdline for IOMMU mode
	cmdline := readCmdline()
	mode = ""

	if strings.Contains(cmdline, "iommu=pt") {
		mode = "pt"
	} else if strings.Contains(cmdline, "iommu=strict") {
		mode = "strict"
	} else if strings.Contains(cmdline, "intel_iommu=on") {
		mode = "on"
	} else if strings.Contains(cmdline, "amd_iommu=on") {
		mode = "on"
	} else if strings.Contains(cmdline, "iommu=off") || strings.Contains(cmdline, "intel_iommu=off") {
		// IOMMU present but explicitly disabled
		return "disabled", groups, "off"
	}

	// IOMMU groups exist and not explicitly disabled
	if mode != "" {
		return "active", groups, mode
	}
	// Groups exist but no cmdline parameter — likely active by default
	return "active", groups, "default"
}

// detectThunderbolt checks for Thunderbolt devices.
func detectThunderbolt() (status string, count int) {
	entries, err := os.ReadDir("/sys/bus/thunderbolt/devices/")
	if err != nil {
		return "absent", 0
	}
	// Count actual device entries (not domain controllers)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "domain") {
			continue
		}
		count++
	}
	if count > 0 {
		return "present", count
	}
	// Only domains exist — Thunderbolt controller present but no devices attached
	if len(entries) > 0 {
		return "controller-only", len(entries)
	}
	return "absent", 0
}

// detectModuleSigs checks if kernel module signatures enforcement is active.
func detectModuleSigs() string {
	// If lockdown is active at integrity or confidentiality level,
	// module signatures are implicitly enforced.
	lockdown := detectLockdown()
	if lockdown == "confidentiality" || lockdown == "integrity" {
		return "enforced"
	}

	// Check /proc/sys/kernel/module_sig_enforce
	data, err := os.ReadFile("/proc/sys/kernel/module_sig_enforce")
	if err != nil {
		// File might not exist if CONFIG_MODULE_SIG is not set
		return "n/a"
	}
	val := strings.TrimSpace(string(data))
	if val == "1" {
		return "enforced"
	}
	return "not-enforced"
}

// detectLockdown reads the kernel lockdown state.
// The format is: "none integrity [confidentiality]" where the bracketed
// value is the current state.
func detectLockdown() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return "unknown"
	}
	s := strings.TrimSpace(string(data))
	for _, word := range strings.Fields(s) {
		if strings.HasPrefix(word, "[") && strings.HasSuffix(word, "]") {
			return strings.Trim(word, "[]")
		}
	}
	return "none"
}

// detectMemoryEncryption checks for AMD SME, Intel TME, or AMD TSME.
func detectMemoryEncryption() (status string, encType string, advice string) {
	// Detect CPU vendor
	vendor := detectCPUVendor()

	cmdline := readCmdline()

	if vendor == "amd" {
		// AMD SME: check cmdline for mem_encrypt=on
		if strings.Contains(cmdline, "mem_encrypt=on") || strings.Contains(cmdline, "mem_encrypt=active") {
			return "active", "AMD SME", ""
		}

		// AMD TSME: check for tsme_status sysfs files
		tsmeActive, _ := detectTSME()
		if tsmeActive {
			return "active", "AMD TSME", ""
		}

		// Check if SME is available but not active
		if strings.Contains(cmdline, "mem_encrypt=") {
			// Present in cmdline but not "on" — could be "off"
			return "disabled", "AMD SME", "Enable AMD SME: add mem_encrypt=on to kernel cmdline and enable in BIOS"
		}

		// Check if AMD memory encryption is compiled into the kernel
		// by checking /proc/cpuinfo for SME support (flag may not be present
		// if BIOS hasn't enabled it)
		if hasCPUFlag("sme") {
			return "active", "AMD SME", ""
		}

		// SME might be available but not enabled — check if the kernel has the config
		if fileExists("/sys/module/kvm_amd/parameters/sev") || fileExists("/sys/module/kvm_amd/parameters/sev_es") {
			return "available", "AMD SME", "Enable AMD SME: add mem_encrypt=on to kernel cmdline and enable in BIOS for cold boot attack resistance"
		}

		return "not-available", "", "AMD memory encryption (SME) not detected. Enable in BIOS and add mem_encrypt=on to kernel cmdline for cold boot attack resistance"

	} else if vendor == "intel" {
		// Intel TME: check /proc/cpuinfo for "tme" flag
		if hasCPUFlag("tme") {
			return "active", "Intel TME", ""
		}

		// Check dmesg for TME activation message
		if dmesgContains("x86/tme: enabled by BIOS") {
			return "active", "Intel TME", ""
		}

		// Check if TME is available but not enabled
		if dmesgContains("x86/tme: not enabled by BIOS") {
			return "available", "Intel TME", "Enable Intel TME (Total Memory Encryption) in BIOS setup for cold boot attack resistance"
		}

		return "not-available", "", "Intel TME not detected. Enable in BIOS setup for cold boot attack resistance"

	} else if tsmeActive, _ := detectTSME(); tsmeActive {
		return "active", "TSME", ""
	}

	return "not-available", "", "Memory encryption not available on this platform"
}

// detectTSME checks for AMD Transparent Secure Memory Encryption via sysfs.
// TSME is a BIOS-controlled always-on feature, not cmdline-activated.
func detectTSME() (active bool, count int) {
	// Search for tsme_status files under /sys/devices/
	matches, err := filepath.Glob("/sys/devices/**/tsme_status")
	if err != nil || len(matches) == 0 {
		return false, 0
	}
	count = len(matches)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(data))
		if val == "1" {
			return true, count
		}
	}
	return false, count
}

// detectCPUVendor reads the CPU vendor from /proc/cpuinfo.
func detectCPUVendor() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	s := string(data)
	if strings.Contains(s, "AuthenticAMD") {
		return "amd"
	}
	if strings.Contains(s, "GenuineIntel") {
		return "intel"
	}
	return "unknown"
}

// hasCPUFlag checks if a specific flag is present in /proc/cpuinfo.
func hasCPUFlag(flag string) bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	// Look for the flag in the "flags" line
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags") {
			return strings.Contains(line, " "+flag+" ") || strings.Contains(line, " "+flag+"\n")
		}
	}
	return false
}

// readCmdline reads the kernel command line.
func readCmdline() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return string(data)
}

// fileExists checks if a file exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dmesgContains checks if the kernel log contains a specific string.
// Uses /dev/kmsg for reading (available to root).
func dmesgContains(pattern string) bool {
	// Try reading from /dev/kmsg (requires root)
	data, err := os.ReadFile("/dev/kmsg")
	if err != nil {
		// Fallback: try journalctl if available
		return false
	}
	return strings.Contains(string(data), pattern)
}

// checkHardwareWarnings generates warnings based on hardware security status.
func checkHardwareWarnings(info *hardwareSecurityInfo) []string {
	var warnings []string

	// TPM Bus Encryption
	if info.TPMBusEncryption != "active" {
		warnings = append(warnings, "WARNING: TPM bus encryption inactive — LUKS key and TOTP seed may be readable via bus sniffing. Enable CONFIG_TCG_TPM2_HMAC in kernel config.")
	}

	// IOMMU + Thunderbolt
	if info.Thunderbolt == "present" && info.IOMMU != "active" {
		warnings = append(warnings, "CRITICAL: Thunderbolt devices present without IOMMU protection — DMA attack can extract keys from RAM during boot")
	} else if info.Thunderbolt == "present" && info.IOMMU == "active" {
		// OK — Thunderbolt protected by IOMMU
	} else if info.IOMMU == "inactive" || info.IOMMU == "disabled" {
		warnings = append(warnings, "WARNING: IOMMU not active — DMA-capable PCIe devices may access arbitrary RAM. Enable IOMMU (iommu=pt or intel_iommu=on in kernel cmdline).")
	}

	// Module Signatures
	if info.ModuleSigs == "not-enforced" {
		warnings = append(warnings, "WARNING: Module signatures not enforced — malicious kernel modules can be loaded. Enable lockdown=integrity or module.sig_enforce=1.")
	}

	// Lockdown
	if info.Lockdown == "none" {
		warnings = append(warnings, "WARNING: Kernel lockdown not active — /dev/mem, kexec, and BPF are accessible. Enable lockdown via Secure Boot or kernel cmdline.")
	} else if info.Lockdown == "integrity" {
		// OK — integrity mode blocks kernel modification
	} else if info.Lockdown == "confidentiality" {
		// Best — also blocks memory access
	}

	// Memory Encryption
	if info.MemoryEncryption == "not-available" && info.MemEncryptAdvice != "" {
		warnings = append(warnings, "INFO: "+info.MemEncryptAdvice)
	} else if info.MemoryEncryption == "available" && info.MemEncryptAdvice != "" {
		warnings = append(warnings, "WARNING: "+info.MemEncryptAdvice)
	} else if info.MemoryEncryption == "disabled" && info.MemEncryptAdvice != "" {
		warnings = append(warnings, "WARNING: "+info.MemEncryptAdvice)
	}

	return warnings
}

// (renderHardwareSecurity removed — threat-model view in status.go replaces it)

// detectFirmwareTPM checks whether the TPM is a firmware TPM (fTPM) running
// inside the AMD PSP / Intel ME, or a discrete TPM chip on the motherboard.
// Returns true if fTPM (CRB driver), false if discrete TPM (TIS driver).
//
// With fTPM, there is no external bus between the TPM and CPU — keys never
// leave the SoC die. This makes bus-sniffing attacks impractical, so the
// TPM bus encryption warning can be downgraded to info.
func detectFirmwareTPM() bool {
	link, err := os.Readlink("/sys/class/tpm/tpm0/device/driver")
	if err != nil {
		return false
	}
	return strings.Contains(link, "tpm_crb")
}
