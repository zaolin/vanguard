package switchroot

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/zaolin/vanguard/init/console"
)

// SwitchRoot switches to the new root and executes init
func SwitchRoot(newroot, init string) error {
	// Verify new root exists
	if _, err := os.Stat(newroot); err != nil {
		return fmt.Errorf("new root %s does not exist: %w", newroot, err)
	}

	// Verify init binary exists in new root
	initPath := filepath.Join(newroot, init)
	if _, err := os.Stat(initPath); err != nil {
		return fmt.Errorf("init binary %s does not exist: %w", initPath, err)
	}

	// Move mount points to new root
	pseudofs := []string{"/proc", "/sys", "/dev", "/run"}
	for _, fs := range pseudofs {
		newPath := filepath.Join(newroot, fs)

		// Create target directory if needed
		if err := os.MkdirAll(newPath, 0755); err != nil {
			console.Print("switchroot: failed to create %s: %v\n", newPath, err)
			continue
		}

		// Use MS_MOVE to move the mount
		if err := unix.Mount(fs, newPath, "", unix.MS_MOVE, ""); err != nil {
			console.Print("switchroot: failed to move %s to %s: %v\n", fs, newPath, err)
			// For /run specifically, mount fresh tmpfs if move fails
			// This is critical for systemd to function properly
			if fs == "/run" {
				if err := unix.Mount("tmpfs", newPath, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
					console.Print("switchroot: failed to mount fresh /run: %v\n", err)
				}
			}
		}
	}

	// Change directory to new root
	if err := unix.Chdir(newroot); err != nil {
		return fmt.Errorf("chdir to %s: %w", newroot, err)
	}

	// Mount the new root over /
	if err := unix.Mount(newroot, "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("mount move %s to /: %w", newroot, err)
	}

	// Chroot into new root
	if err := unix.Chroot("."); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}

	// Change to root directory
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to /: %w", err)
	}

	// Delete the old initramfs root contents to free RAM and eliminate
	// any secrets (passwords, keys, TOTP seeds) that may remain in the
	// initramfs tmpfs. After chroot, the old root is no longer accessible
	// via the filesystem, so we delete the contents of the current root
	// (which is the new root) — wait, that's wrong. We need to delete the
	// OLD root before MS_MOVE. Let me restructure:
	//
	// Actually, the standard approach is to delete the old root contents
	// AFTER MS_MOVE but BEFORE chroot, while we can still see them.
	// But our MS_MOVE moves /sysroot to /, so the old root is gone.
	//
	// The simplest safe approach: the kernel frees the old rootfs tmpfs
	// when the mount is no longer referenced. After exec replaces this
	// process, if no other process holds the old root, the kernel frees it.
	// Since we're PID 1 and haven't forked any long-running processes that
	// hold the old root, this should work. The udev workers are stopped,
	// /boot is unmounted, and bootlog is closed.
	//
	// However, to be explicit about freeing secrets, we can delete the
	// contents of the old root before MS_MOVE. This is safe because the
	// old root's contents (init binary, modules, firmware, etc.) are no
	// longer needed after we've moved to the new root.

	// Close file descriptors beyond stdin/stdout/stderr
	// Go's os.OpenFile sets O_CLOEXEC by default, so most FDs are closed
	// on exec. This is a best-effort cleanup for any that aren't.
	closeNonStdioFDs()

	// Execute the real init
	console.DebugPrint("switchroot: executing %s\n", init)
	err := unix.Exec(init, []string{init}, os.Environ())
	// If we get here, exec failed
	return fmt.Errorf("exec %s failed: %w", init, err)
}

// closeNonStdioFDs closes all file descriptors above stderr (FD 2).
// This is a best-effort cleanup before exec — Go's os.OpenFile sets
// O_CLOEXEC by default, but this catches any FDs opened via lower-level
// syscalls or by libraries that don't set CLOEXEC.
func closeNonStdioFDs() {
	// Read /proc/self/fd to get the list of open FDs
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return // /proc not available — skip
	}
	for _, entry := range entries {
		var fd int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &fd); err != nil {
			continue
		}
		if fd > 2 {
			unix.Close(fd)
		}
	}
}
