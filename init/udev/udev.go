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

	// Write db_persist udev rule for DM devices so they survive switch_root.
	// This matches dracut-ng's modules.d/70dm/11-dm.rules behavior.
	// Without db_persist, initrd-udevadm-cleanup-db.service deletes all
	// DM device database entries during switch_root, causing /dev/mapper/*
	// and /dev/<vg>/<lv> symlinks to disappear in the real system.
	if err := writeDBPersistRule(); err != nil {
		console.DebugPrint("udev: db_persist rule write failed: %v\n", err)
	}

	// Reload udev rules so the db_persist rule takes effect.
	// Use findBinary like the udevd start path — hardcoding udevadmPaths[0]
	// silently skips the reload when /usr/bin/udevadm is missing (Gentoo
	// ships /sbin/udevadm), which would drop the db_persist rule and lose
	// /dev/mapper symlinks at switch_root.
	udevadm := findBinary(udevadmPaths)
	if udevadm != "" {
		reloadCmd := exec.Command(udevadm, "control", "--reload")
		reloadCmd.Run()
	}

	return nil
}

func writeDBPersistRule() error {
	if err := os.MkdirAll("/run/udev/rules.d", 0755); err != nil {
		return err
	}
	return os.WriteFile("/run/udev/rules.d/99-dm-persist.rules", []byte(
		"SUBSYSTEM!=\"block\", GOTO=\"dm_persist_end\"\n"+
			"KERNEL!=\"dm-[0-9]*\", GOTO=\"dm_persist_end\"\n"+
			"ACTION!=\"add|change\", GOTO=\"dm_persist_end\"\n"+
			"OPTIONS+=\"db_persist\"\n"+
			"LABEL=\"dm_persist_end\"\n",
	), 0644)
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

// CleanupDB is no longer needed - db_persist udev rule (99-dm-persist.rules)
// automatically preserves DM device database entries across switch_root.
// The cleanup happens implicitly when udevd stops gracefully.
func CleanupDB() error {
	console.DebugPrint("udev: db_persist rule handles DM device persistence\n")
	return nil
}

// findBinaryFn resolves a binary from a list of candidate paths, and
// udevadmRunner executes udevadm. Both are package variables so the udev
// stop path can be tested without udevadm installed.
var (
	findBinaryFn  = findBinary
	udevadmRunner = func(binary string, args ...string) error {
		return exec.Command(binary, args...).Run()
	}
)

// udevadmExitArgs returns the args used to stop a daemonized udevd,
// selected so tests can pin the mechanism.
func udevadmExitArgs() []string {
	return []string{"control", "--exit"}
}

// Stop terminates the udevd daemon gracefully.
//
// Start() launches udevd with --daemon: it forks, and its immediate child
// exits; udevdCmd.Process therefore refers to a dead pid. Signaling or
// waiting on that pid can never stop the real daemon — the surviving
// udevd would then compete with the system's own systemd-udevd.service
// after switch_root. The reliable way to stop a daemonized udevd is
// `udevadm control --exit`, which talks to the running daemon over its
// control socket and waits for it to exit. The direct signal is kept only
// as a fallback for a foreground start.
func Stop() {
	// Preferred: ask the running daemon to exit over the control socket.
	udevadm := findBinaryFn(udevadmPaths)
	if udevadm != "" {
		if err := udevadmRunner(udevadm, udevadmExitArgs()...); err == nil {
			console.DebugPrint("udev: udevd stopped via udevadm control --exit\n")
			udevdCmd = nil
			return
		} else {
			console.DebugPrint("udev: udevadm control --exit failed: %v\n", err)
		}
	}

	// Fallback: signal the child we started (foreground daemon, or --exit
	// unavailable). If the daemonized parent already exited, this is a
	// no-op on a reaped/dead pid.
	if udevdCmd != nil && udevdCmd.Process != nil {
		console.DebugPrint("udev: stopping udevd via signal\n")

		// Send SIGINT for graceful shutdown
		_ = udevdCmd.Process.Signal(os.Interrupt)

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
			_ = udevdCmd.Process.Kill()
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
