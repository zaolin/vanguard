package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
		if tsmeActive, tsmeCount := detectTSME(); tsmeActive {
			if tsmeCount > 1 {
				return "active", fmt.Sprintf("AMD TSME (%d devices)", tsmeCount), ""
			}
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

		// TME activation is reported in the kernel log. Read it once:
		// reading it spawns dmesg (or opens /dev/kmsg), and the two
		// checks below would otherwise do that twice.
		//
		// A failed read must not be reported as "TME not detected":
		// the state is unknown, so say so.
		log, err := readKernelLog()
		if err != nil {
			return "not-available", "", fmt.Sprintf("Intel TME could not be detected (kernel log unavailable: %v). Enable Intel TME in BIOS setup for cold boot attack resistance", err)
		}
		if strings.Contains(log, "x86/tme: enabled by BIOS") {
			return "active", "Intel TME", ""
		}
		if strings.Contains(log, "x86/tme: not enabled by BIOS") {
			return "available", "Intel TME", "Enable Intel TME (Total Memory Encryption) in BIOS setup for cold boot attack resistance"
		}

		return "not-available", "", "Intel TME not detected. Enable in BIOS setup for cold boot attack resistance"

	} else if tsmeActive, _ := detectTSME(); tsmeActive {
		return "active", "TSME", ""
	}

	return "not-available", "", "Memory encryption not available on this platform"
}

// memoryEncryptionActiveNow reports whether RAM encryption is actually active
// right now, based on positive kernel evidence — not on CPU flags or on a boot
// parameter that merely REQUESTS it.
//
// mem_encrypt=on only asks for SME: on a CPU or kernel without support it does
// nothing. Treating it as proof would suppress a real suspend-to-RAM warning.
func memoryEncryptionActiveNow() bool {
	// TSME is reported directly by the driver, which is authoritative.
	if active, _ := detectTSMEFn(); active {
		return true
	}

	log, err := readKernelLog()
	if err != nil {
		return false
	}
	// Intel: the kernel states explicitly whether TME was enabled.
	if strings.Contains(log, "x86/tme: enabled by BIOS") {
		return true
	}
	if strings.Contains(log, "x86/tme: not enabled by BIOS") {
		return false
	}
	// AMD: mem_encrypt.c prints this only when the features are active
	// (verified in arch/x86/mm/mem_encrypt.c: print_mem_encrypt_feature_info).
	return strings.Contains(log, "Memory Encryption Features active")
}

// detectTSMEFn is the TSME probe, as a variable so tests can stub it.
var detectTSMEFn = detectTSME

// detectTSME checks for AMD Transparent Secure Memory Encryption via sysfs.
// TSME is a BIOS-controlled always-on feature, not cmdline-activated.
func detectTSME() (active bool, count int) {
	return detectTSMEIn(sysDevicesRoot)
}

// sysDevicesRoot is the sysfs directory tree the TSME lookup walks.
const sysDevicesRoot = "/sys/devices"

// tsmeStatusFile is the sysfs attribute the AMD TSME driver exposes.
const tsmeStatusFile = "tsme_status"

// detectTSMEIn searches root recursively for tsme_status files and reports
// whether any of them report TSME as active.
//
// The lookup must recurse: on real hardware the file lives several levels
// deep (e.g. /sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2/tsme_status).
// A filepath.Glob with a "**" pattern cannot be used — Go's Glob has no
// recursive wildcard and would only match a single path segment.
func detectTSMEIn(root string) (active bool, count int) {
	// The callback never returns an error, so the walk always succeeds;
	// the returned error is only non-nil for a broken root.
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable subtrees (permission, disappearing devices) must
			// not abort the search.
			return nil
		}
		if d.IsDir() || d.Name() != tsmeStatusFile {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			// A device whose status cannot be read tells us nothing:
			// count only devices with a readable status so the reported
			// device count matches what was actually inspected.
			return nil
		}
		count++
		if strings.TrimSpace(string(data)) == "1" {
			active = true
		}
		return nil
	}); err != nil {
		// A completely unreadable sysfs tree means no TSME could be
		// detected — report it as inactive rather than claiming a result.
		return false, count
	}
	return active, count
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

// dmesgTimeout bounds the dmesg(8) invocation.
const dmesgTimeout = 5 * time.Second

// maxKernelLogBytes caps how much kernel log is read into memory.
const maxKernelLogBytes = 256 * 1024

// dmesgRunner runs dmesg(8) and returns its output. It is a package
// variable so the kernel-log reading can be tested without dmesg.
var dmesgRunner = func() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dmesgTimeout)
	defer cancel()
	// No --color flag: dmesg only colorizes when stdout is a terminal,
	// and the option does not exist before util-linux 2.38 — passing it
	// there would fail the whole command.
	return exec.CommandContext(ctx, "dmesg").Output()
}

// kmsgReader reads the kernel log from /dev/kmsg. It is a package
// variable so the reading can be tested without the real device.
var kmsgReader = func() (string, error) {
	return readKmsg("/dev/kmsg")
}

// readKmsg reads the kernel log from path.
//
// It must use raw syscalls: os.File.Read registers the descriptor with the
// Go runtime poller, which turns an EAGAIN into a wait for the next kernel
// record — exactly the hang this code must avoid. /dev/kmsg has no EOF, so
// a blocking read would wait forever on a quiet system.
func readKmsg(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer syscall.Close(fd)

	var out []byte
	buf := make([]byte, 16*1024)
	for len(out) < maxKernelLogBytes {
		n, err := syscall.Read(fd, buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			// Ring buffer drained — done.
			break
		}
		if err != nil {
			if len(out) > 0 {
				break
			}
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		if n == 0 {
			break
		}
	}
	if len(out) == 0 {
		return "", fmt.Errorf("no kernel log data available")
	}
	return string(out), nil
}

// readKernelLog returns the kernel log contents.
//
// It prefers dmesg(8), which handles the ring buffer correctly and yields
// plain text. The /dev/kmsg fallback reads with raw non-blocking syscalls:
// /dev/kmsg has no EOF, and a blocking read would wait for the next kernel
// record to appear.
func readKernelLog() (string, error) {
	out, dmesgErr := dmesgRunner()
	if dmesgErr == nil {
		return string(out), nil
	}
	log, kmsgErr := kmsgReader()
	if kmsgErr != nil {
		return "", fmt.Errorf("dmesg failed: %w; /dev/kmsg failed: %w", dmesgErr, kmsgErr)
	}
	return log, nil
}

// checkHardwareWarnings generates warnings based on hardware security status.
func checkHardwareWarnings(info *hardwareSecurityInfo) []string {
	var warnings []string

	// TPM Bus Encryption
	if info.TPMBusEncryption != "active" {
		warnings = append(warnings, "WARNING: TPM bus encryption inactive — LUKS key and HOTP seed may be readable via bus sniffing. Enable CONFIG_TCG_TPM2_HMAC in kernel config.")
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
