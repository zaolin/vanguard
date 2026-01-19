package fsck

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Debug function placeholder - will be set by the main init package
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// fsck binary search paths
var fsckPaths = []string{
	"/usr/bin/fsck",
	"/sbin/fsck",
	"/bin/fsck",
}

// Filesystem-specific fsck binaries
var fsckBinaries = map[string][]string{
	"ext4":  {"/usr/bin/fsck.ext4", "/sbin/fsck.ext4", "/usr/bin/e2fsck", "/sbin/e2fsck"},
	"ext3":  {"/usr/bin/fsck.ext3", "/sbin/fsck.ext3", "/usr/bin/e2fsck", "/sbin/e2fsck"},
	"ext2":  {"/usr/bin/fsck.ext2", "/sbin/fsck.ext2", "/usr/bin/e2fsck", "/sbin/e2fsck"},
	"xfs":   {"/usr/bin/xfs_repair", "/sbin/xfs_repair"},
	"btrfs": {"/usr/bin/btrfs", "/sbin/btrfs"}, // btrfs check is usually not run at boot
}

// Exit codes from fsck (can be OR'd together)
const (
	FsckOK             = 0   // No errors
	FsckCorrected      = 1   // Filesystem errors corrected
	FsckRebootRequired = 2   // System should be rebooted
	FsckUncorrected    = 4   // Filesystem errors left uncorrected
	FsckOperational    = 8   // Operational error
	FsckUsage          = 16  // Usage or syntax error
	FsckCanceled       = 32  // Checking canceled by user request
	FsckSharedLib      = 128 // Shared-library error
)

// Check runs filesystem check on the given device before mounting.
// Returns nil if the filesystem is clean or errors were corrected.
// Returns an error if there are uncorrectable errors or fsck fails.
//
// The fsck is run with -y flag to automatically fix errors.
// For XFS, xfs_repair is used instead (but only in check mode by default).
func Check(device, fstype string) error {
	// Check if fsck is disabled via kernel cmdline
	if isFsckDisabled() {
		Debug("fsck: disabled via kernel cmdline\n")
		return nil
	}

	// Find appropriate fsck binary
	binary := findFsckBinary(fstype)
	if binary == "" {
		Debug("fsck: no fsck binary found for %s, skipping\n", fstype)
		return nil
	}

	Debug("fsck: checking %s (%s) with %s\n", device, fstype, binary)

	// Build command based on filesystem type
	var cmd *exec.Cmd
	switch fstype {
	case "xfs":
		// xfs_repair -n for check-only mode (non-destructive)
		// Use -n to just check; actual repair would need unmounted fs
		cmd = exec.Command(binary, "-n", device)
	case "btrfs":
		// btrfs check is typically not run at boot time
		// It requires the filesystem to be unmounted and can be slow
		Debug("fsck: skipping btrfs (check not recommended at boot)\n")
		return nil
	default:
		// For ext2/3/4 and others: fsck -y (auto-yes to fixes)
		// -y: assume yes to all questions
		// -C 0: show progress on fd 0 (may not work in initramfs)
		cmd = exec.Command(binary, "-y", device)
	}

	output, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return fmt.Errorf("fsck failed to execute: %w", err)
		}
	}

	Debug("fsck: exit code %d\n", exitCode)
	if len(output) > 0 {
		Debug("fsck: output: %s\n", strings.TrimSpace(string(output)))
	}

	// Interpret exit code
	// 0 = clean
	// 1 = errors corrected
	// 2 = system should be rebooted (we'll continue and let systemd handle it)
	// 4+ = errors not corrected (fatal)
	if exitCode&FsckUncorrected != 0 {
		return fmt.Errorf("fsck found uncorrectable errors on %s", device)
	}
	if exitCode&FsckOperational != 0 {
		return fmt.Errorf("fsck operational error on %s", device)
	}

	if exitCode&FsckCorrected != 0 {
		Debug("fsck: errors corrected on %s\n", device)
	}
	if exitCode&FsckRebootRequired != 0 {
		Debug("fsck: reboot may be required after mounting %s\n", device)
	}

	return nil
}

// isFsckDisabled checks if fsck is disabled via kernel cmdline
// Supports: vanguard.fsck=0, fsck.mode=skip
func isFsckDisabled() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		// vanguard-specific parameter
		if param == "vanguard.fsck=0" || param == "vanguard.fsck=no" {
			return true
		}
		// systemd-compatible parameter
		if param == "fsck.mode=skip" {
			return true
		}
	}
	return false
}

// findFsckBinary finds the appropriate fsck binary for the given filesystem type
func findFsckBinary(fstype string) string {
	// First try filesystem-specific binary
	if paths, ok := fsckBinaries[fstype]; ok {
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	// Fall back to generic fsck (it will call the right helper)
	for _, path := range fsckPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// CheckEnabled returns true if fsck checking is enabled
func CheckEnabled() bool {
	return !isFsckDisabled()
}
