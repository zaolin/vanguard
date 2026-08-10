package main

import (
	"encoding/json"
	"os/exec"
	"sort"
)

// fwupdInfo contains platform security data from fwupd's HSI (Hardware
// Security Interface). fwupd is an optional tool — if not installed, all
// fields are empty/zero and the threat model silently skips fwupd-based
// checks, falling back to HSTI sysfs and our own detectors.
type fwupdInfo struct {
	Installed  bool                 `json:"installed"`
	HSILevel   int                  `json:"hsiLevel,omitempty"`
	Attributes map[string]fwupdAttr `json:"attributes,omitempty"`
}

// fwupdAttr represents a single fwupd HSI attribute result.
type fwupdAttr struct {
	Result   string   `json:"result"`
	HsiLevel int      `json:"hsiLevel"`
	Success  bool     `json:"success"`
	Flags    []string `json:"flags,omitempty"`
}

// fwupd HSI AppstreamId constants for the attributes we consume.
const (
	fwupdUefiSecureBoot         = "org.fwupd.hsi.Uefi.SecureBoot"
	fwupdUefiPk                 = "org.fwupd.hsi.Uefi.Pk"
	fwupdPlatformFused          = "org.fwupd.hsi.PlatformFused"
	fwupdAmdPlatformSecureBoot  = "org.fwupd.hsi.Amd.PlatformSecureBoot"
	fwupdTpmReconstructionPcr0  = "org.fwupd.hsi.Tpm.ReconstructionPcr0"
	fwupdTpmEmptyPcr            = "org.fwupd.hsi.Tpm.EmptyPcr"
	fwupdTpmVersion20           = "org.fwupd.hsi.Tpm.Version20"
	fwupdIommu                  = "org.fwupd.hsi.Iommu"
	fwupdPrebootDma             = "org.fwupd.hsi.PrebootDma"
	fwupdKernelLockdown         = "org.fwupd.hsi.Kernel.Lockdown"
	fwupdKernelTainted          = "org.fwupd.hsi.Kernel.Tainted"
	fwupdCetActive              = "org.fwupd.hsi.Cet.Active"
	fwupdCetEnabled             = "org.fwupd.hsi.Cet.Enabled"
	fwupdSmap                   = "org.fwupd.hsi.Smap"
	fwupdEncryptedRam           = "org.fwupd.hsi.EncryptedRam"
	fwupdPlatformDebugLocked    = "org.fwupd.hsi.PlatformDebugLocked"
	fwupdAmdSpiWriteProtection  = "org.fwupd.hsi.Amd.SpiWriteProtection"
	fwupdAmdSpiReplayProtection = "org.fwupd.hsi.Amd.SpiReplayProtection"
	fwupdAmdRollbackProtection  = "org.fwupd.hsi.Amd.RollbackProtection"
	fwupdAmdSmmLocked           = "org.fwupd.hsi.Amd.SmmLocked"
)

// collectFwupdStatus gathers fwupd HSI data if fwupdmgr is installed.
// Returns Installed=false if fwupdmgr is not on PATH (silent skip).
func collectFwupdStatus() *fwupdInfo {
	info := &fwupdInfo{}

	if _, err := exec.LookPath("fwupdmgr"); err != nil {
		return info
	}
	info.Installed = true

	output, err := exec.Command("fwupdmgr", "security", "--json").Output()
	if err != nil {
		return info
	}

	var raw struct {
		SecurityAttributes []struct {
			AppstreamID string   `json:"AppstreamId"`
			HsiResult   string   `json:"HsiResult"`
			HsiLevel    int      `json:"HsiLevel"`
			Flags       []string `json:"Flags"`
		} `json:"SecurityAttributes"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return info
	}

	info.Attributes = make(map[string]fwupdAttr)
	for _, a := range raw.SecurityAttributes {
		attr := fwupdAttr{
			Result:   a.HsiResult,
			HsiLevel: a.HsiLevel,
			Success:  containsFlag(a.Flags, "success"),
			Flags:    a.Flags,
		}
		info.Attributes[a.AppstreamID] = attr
	}

	info.HSILevel = computeHSILevel(info.Attributes)
	return info
}

// computeHSILevel returns the highest HSI level where all attributes pass.
func computeHSILevel(attrs map[string]fwupdAttr) int {
	byLevel := make(map[int][]bool)
	for _, a := range attrs {
		if a.HsiLevel <= 0 {
			continue
		}
		byLevel[a.HsiLevel] = append(byLevel[a.HsiLevel], a.Success)
	}

	levels := make([]int, 0, len(byLevel))
	for l := range byLevel {
		levels = append(levels, l)
	}
	sort.Ints(levels)

	composite := 0
	for _, l := range levels {
		allPass := true
		for _, ok := range byLevel[l] {
			if !ok {
				allPass = false
				break
			}
		}
		if allPass {
			composite = l
		} else {
			break
		}
	}
	return composite
}

// fwupdAttr returns the fwupd attribute for the given AppstreamId, or nil.
func (f *fwupdInfo) attr(name string) *fwupdAttr {
	if f == nil || f.Attributes == nil {
		return nil
	}
	if a, ok := f.Attributes[name]; ok {
		return &a
	}
	return nil
}

// fwupdSuccess returns true if the given attribute exists and passed.
func (f *fwupdInfo) success(name string) bool {
	a := f.attr(name)
	return a != nil && a.Success
}

// fwupdPresent returns true if the given attribute exists (regardless of pass/fail).
func (f *fwupdInfo) present(name string) bool {
	return f.attr(name) != nil
}

// fwupdResult returns the HsiResult string for the given attribute, or "" if absent.
func (f *fwupdInfo) result(name string) string {
	a := f.attr(name)
	if a == nil {
		return ""
	}
	return a.Result
}

func containsFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}
