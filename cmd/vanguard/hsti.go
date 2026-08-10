package main

import (
	"os"
	"path/filepath"
	"strings"
)

// hstiInfo contains AMD PSP HSTI (Hardware Security Test Interface)
// security attributes read from sysfs. Used as fallback when fwupd
// is not installed. Only available on AMD platforms with the CCP/PSP driver.
type hstiInfo struct {
	Available             bool `json:"available"`
	FusedPart             int  `json:"fusedPart"`
	BootIntegrity         int  `json:"bootIntegrity"`
	DebugLockOn           int  `json:"debugLockOn"`
	AntiRollbackStatus    int  `json:"antiRollbackStatus"`
	RomArmorEnforced      int  `json:"romArmorEnforced"`
	RpmcProductionEnabled int  `json:"rpmcProductionEnabled"`
	RpmcSpiromAvailable   int  `json:"rpmcSpiromAvailable"`
	HspTpmAvailable       int  `json:"hspTpmAvailable"`
}

// collectHSTIStatus reads AMD PSP HSTI security attributes from sysfs.
// Returns Available=false if the PSP sysfs interface is not found.
func collectHSTIStatus() *hstiInfo {
	info := &hstiInfo{}

	// The PSP security attributes are under /sys/bus/pci/drivers/ccp/*/
	// They appear directly on the CCP PCI device, not under a "security" subdirectory.
	matches, err := filepath.Glob("/sys/bus/pci/drivers/ccp/*")
	if err != nil || len(matches) == 0 {
		return info
	}

	// Find the CCP device directory that has the HSTI attributes
	var ccpDir string
	for _, dir := range matches {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "fused_part")); err == nil {
			ccpDir = dir
			break
		}
	}
	if ccpDir == "" {
		return info
	}

	info.Available = true
	info.FusedPart = readHSTIInt(filepath.Join(ccpDir, "fused_part"))
	info.BootIntegrity = readHSTIInt(filepath.Join(ccpDir, "boot_integrity"))
	info.DebugLockOn = readHSTIInt(filepath.Join(ccpDir, "debug_lock_on"))
	info.AntiRollbackStatus = readHSTIInt(filepath.Join(ccpDir, "anti_rollback_status"))
	info.RomArmorEnforced = readHSTIInt(filepath.Join(ccpDir, "rom_armor_enforced"))
	info.RpmcProductionEnabled = readHSTIInt(filepath.Join(ccpDir, "rpmc_production_enabled"))
	info.RpmcSpiromAvailable = readHSTIInt(filepath.Join(ccpDir, "rpmc_spirom_available"))
	info.HspTpmAvailable = readHSTIInt(filepath.Join(ccpDir, "hsp_tpm_available"))

	return info
}

// readHSTIInt reads a sysfs file containing "0" or "1" and returns the int value.
func readHSTIInt(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "1" {
		return 1
	}
	return 0
}
