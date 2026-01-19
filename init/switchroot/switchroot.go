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

	// Close file descriptors (keep stdin, stdout, stderr)
	// This helps clean up the initramfs

	// Execute the real init
	console.DebugPrint("switchroot: executing %s\n", init)
	err := unix.Exec(init, []string{init}, os.Environ())
	// If we get here, exec failed
	return fmt.Errorf("exec %s failed: %w", init, err)
}
