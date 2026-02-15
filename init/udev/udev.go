package udev

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/zaolin/vanguard/init/console"
)

var udevdPaths = []string{
	"/usr/lib/systemd/systemd-udevd",
	"/lib/systemd/systemd-udevd",
	"/sbin/udevd",
}

var udevadmPaths = []string{
	"/usr/bin/udevadm",
	"/sbin/udevadm",
	"/bin/udevadm",
}

var udevdCmd *exec.Cmd

// Start launches systemd-udevd daemon
func Start() error {
	udevd := findBinary(udevdPaths)
	if udevd == "" {
		console.DebugPrint("udev: udevd not found, skipping\n")
		return nil
	}

	// Create required directories
	dirs := []string{
		"/run/udev",
		"/run/udev/data",
		"/run/udev/tags",
	}
	for _, dir := range dirs {
		os.MkdirAll(dir, 0755)
	}

	// Start udevd daemon (redirect output to prevent TUI interference)
	console.DebugPrint("udev: starting systemd-udevd\n")
	udevdCmd = exec.Command(udevd, "--daemon", "--resolve-names=never")

	// Redirect output to /dev/null to avoid TUI interference
	devNull, _ := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if devNull != nil {
		udevdCmd.Stdout = devNull
		udevdCmd.Stderr = devNull
	}

	if err := udevdCmd.Start(); err != nil {
		if devNull != nil {
			devNull.Close()
		}
		return fmt.Errorf("failed to start udevd: %w", err)
	}

	// Close devNull after udevd has started (it inherits the fd)
	if devNull != nil {
		devNull.Close()
	}

	// Wait briefly for daemon to initialize
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Trigger triggers udev events for existing devices
func Trigger() error {
	udevadm := findBinary(udevadmPaths)
	if udevadm == "" {
		return nil
	}

	console.DebugPrint("udev: triggering device events\n")

	// Trigger subsystems
	cmd := exec.Command(udevadm, "trigger", "--type=subsystems", "--action=add")
	cmd.Run()

	// Trigger devices
	cmd = exec.Command(udevadm, "trigger", "--type=devices", "--action=add")
	cmd.Run()

	return nil
}

// TriggerGraphics triggers udev events for graphics and DRM subsystems.
// This ensures /dev/dri/card* and /dev/dri/renderD* devices are created
// with proper permissions before switch_root.
func TriggerGraphics() error {
	udevadm := findBinary(udevadmPaths)
	if udevadm == "" {
		return nil
	}

	console.DebugPrint("udev: triggering graphics and DRM subsystems\n")

	// Trigger DRM subsystem (creates /dev/dri/card* with proper permissions)
	cmd := exec.Command(udevadm, "trigger", "--subsystem-match=drm", "--action=add")
	cmd.Run()

	// Trigger graphics subsystem (for framebuffer devices)
	cmd = exec.Command(udevadm, "trigger", "--subsystem-match=graphics", "--action=add")
	cmd.Run()

	return nil
}

// Settle waits for udev event queue to empty
func Settle(timeout time.Duration) error {
	udevadm := findBinary(udevadmPaths)
	if udevadm == "" {
		return nil
	}

	console.DebugPrint("udev: waiting for events to settle\n")
	cmd := exec.Command(udevadm, "settle", fmt.Sprintf("--timeout=%d", int(timeout.Seconds())))
	return cmd.Run()
}

// CleanupDB cleans up the udev database before switch_root.
// Device-mapper devices with db_persist flag will survive this cleanup,
// allowing systemd on the real root to see them.
func CleanupDB() error {
	udevadm := findBinary(udevadmPaths)
	if udevadm == "" {
		return nil
	}

	console.DebugPrint("udev: cleaning up database (db_persist devices will survive)\n")
	cmd := exec.Command(udevadm, "info", "--cleanup-db")

	// Redirect output to /dev/null to avoid TUI interference
	devNull, _ := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if devNull != nil {
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		defer devNull.Close()
	}

	return cmd.Run()
}

// Stop terminates udevd daemon gracefully using SIGTERM.
// This allows udevd to clean up properly before switch_root.
func Stop() {
	if udevdCmd != nil && udevdCmd.Process != nil {
		console.DebugPrint("udev: stopping udevd gracefully\n")

		// Send SIGTERM for graceful shutdown
		udevdCmd.Process.Signal(os.Interrupt)

		// Wait with timeout for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- udevdCmd.Wait()
		}()

		select {
		case <-done:
			// Graceful shutdown completed
		case <-time.After(2 * time.Second):
			// Timeout - force kill
			console.DebugPrint("udev: graceful stop timed out, killing\n")
			udevdCmd.Process.Kill()
			<-done
		}
	}
}

func findBinary(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
