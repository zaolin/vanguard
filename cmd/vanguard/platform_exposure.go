package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// swapState classifies a swap area's backing store.
type swapState int

const (
	swapUnknown swapState = iota
	swapEncrypted
	swapPlain
	swapRamBacked
)

// swapEntry describes one active swap area and its backing store.
type swapEntry struct {
	Path  string
	State swapState
}

var (
	swapsFile    = "/proc/swaps"
	mountsFile   = "/proc/mounts"
	sysBlockRoot = "/sys/block"
)

// dmsetupRunner returns `dmsetup table` output for a device-mapper device. It
// is a variable so tests can supply target types without dmsetup.
var dmsetupRunner = func(path string) (string, error) {
	out, err := exec.Command("dmsetup", "table", path).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// swapsReader returns the active swap areas. It is a variable so tests can
// supply fixtures and the read-failure case.
var swapsReader = readActiveSwaps

// readActiveSwaps parses /proc/swaps and classifies each area's backing store.
func readActiveSwaps() ([]swapEntry, error) {
	data, err := os.ReadFile(swapsFile)
	if err != nil {
		return nil, err
	}

	var out []swapEntry
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "Filename" {
			continue
		}
		path := fields[0]
		out = append(out, swapEntry{Path: path, State: classifySwap(path)})
	}
	return out, nil
}

// classifySwap determines a swap area's backing store.
func classifySwap(path string) swapState {
	if strings.HasPrefix(path, "/dev/zram") {
		// zram is compressed RAM only if no backing device is configured.
		// With a backing device, swapped pages go to that disk and its
		// encryption state decides (zram writeback support).
		if backing := zramBackingDev(path); backing != "" {
			if backing == "unknown" {
				return swapUnknown
			}
			return classifySwap(backing)
		}
		return swapRamBacked
	}
	if strings.HasPrefix(path, "/dev/mapper/") || strings.HasPrefix(path, "/dev/dm-") {
		return dmTargetState(path)
	}
	if strings.HasPrefix(path, "/dev/") {
		return swapPlain
	}

	// A swap file is encrypted exactly when the filesystem hosting it sits on
	// dm-crypt (LVM on LUKS), which must be verified by target type as well.
	src := mountSourceForPath(path)
	if src == "" {
		return swapUnknown
	}
	if strings.HasPrefix(src, "/dev/mapper/") || strings.HasPrefix(src, "/dev/dm-") {
		return dmTargetState(src)
	}
	return swapPlain
}

// dmTargetState reports whether a device-mapper device is dm-crypt, by target
// type. Device mapper also provides plaintext LVM, RAID and multipath, so the
// path alone proves nothing.
func dmTargetState(path string) swapState {
	return dmTargetStateDepth(path, 0)
}

// dmTargetStateDepth classifies a device-mapper device by target type,
// recursing into the backing device of linear/striped segments.
//
// LVM on LUKS is a linear target on a dm-crypt PV: without resolving that PV
// the check would call encrypted swap plaintext. RAID/mirror/multipath targets
// are not provably encrypted and yield unknown rather than a false verdict.
func dmTargetStateDepth(path string, depth int) swapState {
	if depth > 4 {
		return swapUnknown
	}

	out, err := dmsetupRunner(path)
	if err != nil {
		return swapUnknown
	}

	sawSegment := false
	result := swapEncrypted
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return swapUnknown
		}
		sawSegment = true

		switch fields[2] {
		case "crypt":
			// This segment is encrypted.
		case "linear":
			// dmsetup reports the backing device as major:minor, not as a
			// path — resolve it before classifying.
			sub := swapUnknown
			if devPath := blockDevResolver(fields[3]); devPath != "" {
				if strings.HasPrefix(devPath, "/dev/mapper/") || strings.HasPrefix(devPath, "/dev/dm-") {
					sub = dmTargetStateDepth(devPath, depth+1)
				} else {
					// A plain block device is never dm-crypt.
					sub = swapPlain
				}
			}
			switch sub {
			case swapPlain:
				return swapPlain // definitively plaintext somewhere
			case swapUnknown:
				result = swapUnknown
			}
		case "striped":
			// Striped tables interleave several devices; not provably
			// encrypted without evaluating all of them.
			return swapUnknown
		default:
			// RAID, mirror, multipath, ...: not provably encrypted.
			return swapUnknown
		}
	}

	if !sawSegment {
		return swapUnknown
	}
	return result
}

// blockDevResolver resolves a dmsetup device reference (major:minor) to a
// device path. /dev/block/<maj>:<min> is the canonical symlink to the device
// node. It is a variable so tests can supply a mapping.
var blockDevResolver = func(ref string) string {
	if target, err := filepath.EvalSymlinks("/dev/block/" + ref); err == nil {
		return target
	}
	return ""
}

// mountSourceForPath returns the source device of the mount that contains
// path, choosing the longest mountpoint that is a proper path ancestor.
func mountSourceForPath(path string) string {
	data, err := os.ReadFile(mountsFile)
	if err != nil {
		return ""
	}

	bestLen := 0
	var bestSrc string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		mountpoint := fields[1]
		if !pathWithin(path, mountpoint) {
			continue
		}
		if len(mountpoint) > bestLen {
			bestLen = len(mountpoint)
			bestSrc = fields[0]
		}
	}
	return bestSrc
}

// pathWithin reports whether path is inside mountpoint on a path-component
// boundary: /home2 is NOT inside /home.
func pathWithin(path, mountpoint string) bool {
	if mountpoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mountpoint || strings.HasPrefix(path, mountpoint+"/")
}

// zramBackingReader returns the backing device configured for a zram device
// (/sys/block/<dev>/backing_dev), or "" when there is none. It is a variable
// so tests can supply a backing device without sysfs.
var zramBackingReader = func(path string) string {
	name := strings.TrimPrefix(path, "/dev/")
	data, err := os.ReadFile(sysBlockRoot + "/" + name + "/backing_dev")
	if err != nil {
		if os.IsNotExist(err) {
			// No backing device configured: zram really is RAM-only.
			return ""
		}
		// A read error is NOT proof that there is no backing device.
		return "unknown"
	}
	dev := strings.TrimSpace(string(data))
	// The kernel reports "none" when there is no backing device.
	if dev == "" || dev == "none" {
		return ""
	}
	// A full path (file_path) is already absolute; a bare kernel device name
	// ("sda3", "dm-0") needs the /dev prefix.
	if strings.HasPrefix(dev, "/") {
		return dev
	}
	return "/dev/" + dev
}

// zramBackingDev resolves a zram device's backing device, if any.
func zramBackingDev(path string) string {
	return zramBackingReader(path)
}

// swapExposure evaluates swap areas for plaintext key material exposure.
func swapExposure(entries []swapEntry, err error) mitigation {
	if err != nil {
		// A failed read is not proof that no swap exists.
		return mitigation{
			Name:   "Swap encryption",
			Status: "info",
			Detail: "could not be read: " + err.Error(),
		}
	}

	if len(entries) == 0 {
		return mitigation{
			Name:   "Swap encryption",
			Status: "info",
			Detail: "no swap configured",
		}
	}

	// Evaluate ALL areas before deciding: a zram or unverified entry must
	// never hide a plaintext swap behind it.
	var plain, unknown, ramBacked string
	for _, e := range entries {
		switch e.State {
		case swapPlain:
			if plain == "" {
				plain = e.Path
			}
		case swapUnknown:
			if unknown == "" {
				unknown = e.Path
			}
		case swapRamBacked:
			if ramBacked == "" {
				ramBacked = e.Path
			}
		}
	}

	if plain != "" {
		return mitigation{
			Name:   "Swap encryption",
			Status: "critical",
			Detail: "unencrypted swap at " + plain + " — the LUKS passphrase can be written to disk in cleartext",
			Fix:    "Move swap onto the encrypted volume or disable it (swapoff " + plain + ")",
		}
	}
	if unknown != "" {
		return mitigation{
			Name:   "Swap encryption",
			Status: "info",
			Detail: "encryption of " + unknown + " could not be verified",
		}
	}
	if ramBacked != "" {
		return mitigation{
			Name:   "Swap encryption",
			Status: "info",
			Detail: ramBacked + " is RAM-backed (zram without a backing device) — no disk exposure",
		}
	}

	return mitigation{
		Name:   "Swap encryption",
		Status: "ok",
		Detail: "all swap areas are on encrypted devices",
	}
}

// sleepStateReader reads /sys/power/state and /sys/power/mem_sleep. An error
// is reported, not converted into "no S3 support".
var sleepStateReader = func() (state, memSleep string, err error) {
	stateData, err := os.ReadFile("/sys/power/state")
	if err != nil {
		return "", "", err
	}
	memSleepData, err := os.ReadFile("/sys/power/mem_sleep")
	if err != nil {
		return string(stateData), "", err
	}
	return string(stateData), string(memSleepData), nil
}

// suspendExposure evaluates whether suspend-to-RAM leaves memory unprotected.
func suspendExposure(state, memSleep string, readErr error, memEncActive bool) mitigation {
	if readErr != nil {
		return mitigation{
			Name:   "Suspend to RAM",
			Status: "info",
			Detail: "could not be read: " + readErr.Error(),
		}
	}

	if !strings.Contains(memSleep, "deep") {
		return mitigation{
			Name:   "Suspend to RAM",
			Status: "info",
			Detail: "no S3 suspend available (s2idle only or no suspend support)",
		}
	}

	if memEncActive {
		return mitigation{
			Name:   "Suspend to RAM",
			Status: "ok",
			Detail: "S3 available with RAM encryption active",
		}
	}

	return mitigation{
		Name:   "Suspend to RAM",
		Status: "warning",
		Detail: "S3 (suspend-to-RAM) is available and RAM is not encrypted — memory contents persist in cleartext during suspend",
		Fix:    "Enable memory encryption (SME/TME) or disable deep suspend: echo s2idle > /sys/power/mem_sleep",
	}
}

// buildPlatformExposureVector reports places where key material or memory
// contents can leak outside the encrypted volume: swap and suspend-to-RAM.
func buildPlatformExposureVector(data *statusData) threatVector {
	v := threatVector{Name: "Platform Data Exposure"}

	entries, err := swapsReader()
	v.Mitigations = append(v.Mitigations, swapExposure(entries, err))

	state, memSleep, sleepErr := sleepStateReader()
	v.Mitigations = append(v.Mitigations, suspendExposure(state, memSleep, sleepErr, memoryEncryptionActiveNow()))

	return v
}

// pcrsAllZero reports whether every PCR with a value is all-zero. With no
// values at all it returns false: an unreadable TPM is not a measurement
// failure, it is unknown.
func pcrsAllZero(results []pcrStatus) bool {
	seen := false
	for _, r := range results {
		if r.Current == "" {
			continue
		}
		seen = true
		if strings.Trim(r.Current, "0") != "" {
			return false
		}
	}
	return seen
}
