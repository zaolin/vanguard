package resume

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Debug function placeholder - will be set by the main init package
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// TryResume attempts to resume from hibernation if resume= parameter is specified.
// This function should be called AFTER LUKS unlock and LVM activation, but BEFORE
// mounting the root filesystem, since the swap device is typically inside the
// encrypted LVM volume.
//
// If resume succeeds, the kernel takes over and this function never returns.
// If no hibernation image exists or resume fails, this function returns nil
// and boot continues normally.
func TryResume() error {
	resumeDev := parseResumeParam()
	if resumeDev == "" {
		Debug("resume: no resume= parameter specified\n")
		return nil
	}

	Debug("resume: attempting resume from %s\n", resumeDev)

	// Normalize LVM path: /dev/vg0/swap -> /dev/mapper/vg0-swap
	resumeDev = normalizeLVMPath(resumeDev)
	Debug("resume: normalized device path: %s\n", resumeDev)

	// Wait for the device to appear (LVM activation may take a moment)
	if err := waitForDevice(resumeDev, 5*time.Second); err != nil {
		Debug("resume: device %s not available: %v\n", resumeDev, err)
		return nil // Continue normal boot
	}

	// Get device major:minor numbers
	var stat unix.Stat_t
	if err := unix.Stat(resumeDev, &stat); err != nil {
		Debug("resume: failed to stat %s: %v\n", resumeDev, err)
		return nil
	}

	major := unix.Major(stat.Rdev)
	minor := unix.Minor(stat.Rdev)
	resumeData := fmt.Sprintf("%d:%d", major, minor)

	Debug("resume: device %s has major:minor %s\n", resumeDev, resumeData)

	// Check for resume_offset (used for swap files)
	offset := parseResumeOffset()
	if offset > 0 {
		Debug("resume: using offset %d\n", offset)
		if err := os.WriteFile("/sys/power/resume_offset", []byte(strconv.FormatInt(offset, 10)), 0644); err != nil {
			Debug("resume: failed to write resume_offset: %v\n", err)
		}
	}

	// Write to /sys/power/resume to trigger resume
	// If a valid hibernation image exists, the kernel will restore memory
	// and resume execution from the hibernation point - this never returns.
	// If no image exists or it's invalid, the write returns normally.
	Debug("resume: writing %s to /sys/power/resume\n", resumeData)
	if err := os.WriteFile("/sys/power/resume", []byte(resumeData), 0644); err != nil {
		Debug("resume: write to /sys/power/resume failed: %v\n", err)
		// Not a fatal error - just means no hibernation image
	}

	// If we get here, resume didn't happen (no image or failed)
	Debug("resume: no hibernation image found, continuing normal boot\n")
	return nil
}

// parseResumeParam extracts the resume= parameter from kernel cmdline
func parseResumeParam() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		if strings.HasPrefix(param, "resume=") {
			return strings.TrimPrefix(param, "resume=")
		}
	}
	return ""
}

// parseResumeOffset extracts the resume_offset= parameter from kernel cmdline
func parseResumeOffset() int64 {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return 0
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		if strings.HasPrefix(param, "resume_offset=") {
			offsetStr := strings.TrimPrefix(param, "resume_offset=")
			offset, err := strconv.ParseInt(offsetStr, 10, 64)
			if err != nil {
				return 0
			}
			return offset
		}
	}
	return 0
}

// normalizeLVMPath converts LVM device paths from /dev/<vg>/<lv> format
// to /dev/mapper/<vg>-<lv> format.
func normalizeLVMPath(device string) string {
	// Already in /dev/mapper/ format
	if strings.HasPrefix(device, "/dev/mapper/") {
		return device
	}

	// Handle UUID= and PARTUUID= references
	if strings.HasPrefix(device, "UUID=") || strings.HasPrefix(device, "PARTUUID=") {
		resolved := resolveDeviceRef(device)
		if resolved != "" {
			return resolved
		}
		return device
	}

	// Check if this looks like /dev/<vg>/<lv> format
	if !strings.HasPrefix(device, "/dev/") {
		return device
	}

	// Extract path after /dev/
	rest := strings.TrimPrefix(device, "/dev/")
	parts := strings.Split(rest, "/")

	// Need exactly 2 parts: vg and lv
	if len(parts) != 2 {
		return device
	}

	vg := parts[0]
	lv := parts[1]

	// Skip known special directories that aren't volume groups
	specialDirs := map[string]bool{
		"disk": true, "block": true, "char": true, "pts": true,
		"shm": true, "mqueue": true, "hugepages": true, "net": true,
		"bus": true, "cpu": true, "input": true, "snd": true, "dri": true,
		"mapper": true,
	}

	if specialDirs[vg] {
		return device
	}

	// Construct the /dev/mapper/<vg>-<lv> path
	// Note: hyphens in VG/LV names are escaped as double hyphens in mapper names
	mapperName := escapeMapperName(vg) + "-" + escapeMapperName(lv)
	mapperPath := filepath.Join("/dev/mapper", mapperName)

	// Check if the mapper path exists, prefer it if so
	if _, err := os.Stat(mapperPath); err == nil {
		return mapperPath
	}

	// Check if original exists
	if _, err := os.Stat(device); err == nil {
		return device
	}

	// Neither exists yet, prefer the mapper path
	return mapperPath
}

// escapeMapperName escapes hyphens in VG/LV names for device-mapper naming
func escapeMapperName(name string) string {
	return strings.ReplaceAll(name, "-", "--")
}

// resolveDeviceRef resolves UUID= or PARTUUID= references to device paths
func resolveDeviceRef(ref string) string {
	if strings.HasPrefix(ref, "UUID=") {
		uuid := strings.TrimPrefix(ref, "UUID=")
		// Check /dev/disk/by-uuid/
		path := filepath.Join("/dev/disk/by-uuid", uuid)
		if target, err := os.Readlink(path); err == nil {
			return filepath.Join("/dev/disk/by-uuid", target)
		}
	} else if strings.HasPrefix(ref, "PARTUUID=") {
		partuuid := strings.TrimPrefix(ref, "PARTUUID=")
		// Check /dev/disk/by-partuuid/
		path := filepath.Join("/dev/disk/by-partuuid", strings.ToLower(partuuid))
		if target, err := os.Readlink(path); err == nil {
			return filepath.Join("/dev/disk/by-partuuid", target)
		}
	}
	return ""
}

// waitForDevice waits for a device to appear with the given timeout
func waitForDevice(device string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if _, err := os.Stat(device); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for device %s", device)
}
