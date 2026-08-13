package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zaolin/vanguard/init/bootlog"
	"github.com/zaolin/vanguard/init/buildtags"
	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/init/fsck"
	"github.com/zaolin/vanguard/init/gpt"
	initluks "github.com/zaolin/vanguard/init/luks"
	"github.com/zaolin/vanguard/init/lvm"
	"github.com/zaolin/vanguard/init/modules"
	"github.com/zaolin/vanguard/init/mount"
	"github.com/zaolin/vanguard/init/resume"
	"github.com/zaolin/vanguard/init/switchroot"
	"github.com/zaolin/vanguard/init/tui"
	"github.com/zaolin/vanguard/init/udev"
	"github.com/zaolin/vanguard/init/vconsole"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// earlyBootMounted tracks whether /boot was mounted during early init.
// Used by cleanupAndHalt to know whether to unmount on failure paths.
var earlyBootMounted bool

// init runs before main(). In test mode, we need to set GOCOVERDIR
// from the kernel cmdline before the Go coverage runtime tries to emit data.
// The coverage runtime checks GOCOVERDIR on process exit, so setting it
// here (before main) ensures it's available.
func init() {
	// /proc/cmdline is available because the kernel mounts procfs
	// before running init (PID 1). This init() runs before main()
	// and before Go's coverage runtime tries to emit data.
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return
	}
	cmdline := string(data)
	// Check for GOCOVERDIR= in cmdline
	for _, param := range strings.Fields(cmdline) {
		if strings.HasPrefix(param, "GOCOVERDIR=") {
			dir := strings.TrimPrefix(param, "GOCOVERDIR=")
			// Create the directory on the rootfs (initramfs tmpfs).
			// The cover disk will be mounted on top later.
			os.MkdirAll(dir, 0755)
			os.Setenv("GOCOVERDIR", dir)
			return
		}
	}
}

func main() {
	// 1. Setup early console for debugging and passphrase prompts
	if err := console.Setup(); err != nil {
		os.Exit(1)
	}

	// Suppress kernel messages (dmesg) on console to avoid cluttering output
	console.SuppressKernelMessages()

	// Enable debug output in console package based on build tag
	console.DebugEnabled = buildtags.DebugEnabled

	buildtags.Debug("vanguard: starting init\n")

	// Pass debug function to packages
	initluks.Debug = buildtags.Debug
	initluks.StrictMode = buildtags.StrictMode
	initluks.LogFunc = func(event string, kvPairs ...string) {
		bootlog.Log(bootlog.Event(event), kvPairs...)
	}

	// 2. Mount essential filesystems
	buildtags.Debug("vanguard: mounting filesystems\n")
	if err := mount.Essential(); err != nil {
		console.Print("vanguard: failed to mount filesystems: %v\n", err)
		halt()
	}

	// Check for test mode (vanguard.testmode=1 in kernel cmdline)
	testMode := isTestMode()
	if testMode {
		console.Print("vanguard: test mode enabled\n")
		// Mount the cover disk (FAT-formatted virtio-blk at /dev/vdb)
		if err := mountTestCoverDisk(); err != nil {
			console.Print("vanguard: warning: cover disk mount failed: %v\n", err)
		}
	}

	// 3. Configure vconsole (keymap + font) BEFORE any password prompts
	buildtags.Debug("vanguard: configuring vconsole\n")
	if err := vconsole.Configure(); err != nil {
		buildtags.Debug("vanguard: vconsole configuration: %v\n", err)
	}

	// Start TUI in non-debug mode (no-op in debug mode)
	if tui.IsEnabled() {
		if err := tui.Start(); err != nil {
			buildtags.Debug("vanguard: TUI start failed: %v\n", err)
		}
		// Note: We quit the TUI explicitly before switch_root, not via defer
		// This ensures proper cleanup of the terminal before exec()
	}

	// 4. Mount /boot early for logging (before anything else)
	buildtags.Debug("vanguard: mounting /boot early\n")
	var err error
	earlyBootMounted, err = mount.MountBootEarly()
	if err != nil {
		buildtags.Debug("vanguard: early mount /boot: %v\n", err)
	}

	// 5. Initialize boot log immediately after /boot is mounted
	if earlyBootMounted {
		if err := bootlog.Init(); err != nil {
			buildtags.Debug("vanguard: bootlog init: %v\n", err)
		} else {
			bootlog.Log(bootlog.EventBootStart)
			bootlog.Log(bootlog.EventEssentialMounts, "status", "ok")
			bootlog.Log(bootlog.EventBootMounted, "status", "ok")

			// Wire up console output to bootlog - all subsequent output will be logged
			console.LogFunc = func(msg string) {
				// Strip trailing newline for cleaner log output
				msg = strings.TrimSuffix(msg, "\n")
				if msg != "" {
					bootlog.Log(bootlog.EventDebug, "msg", msg)
				}
			}
		}
	}

	// 6. Start udevd BEFORE loading modules (for firmware loading)
	tui.UpdateStage(tui.StageUdev)
	buildtags.Debug("vanguard: starting udevd\n")
	if err := udev.Start(); err != nil {
		console.Print("vanguard: warning: udevd start failed: %v\n", err)
		buildtags.Debug("vanguard: udevd start warning: %v\n", err)
	}
	tui.StageDone(tui.StageUdev)

	// 7. Load kernel modules (only those available in the image)
	tui.UpdateStage(tui.StageModules)
	buildtags.Debug("vanguard: loading kernel modules\n")
	availableModules := discoverModules()
	if len(availableModules) > 0 {
		buildtags.Debug("vanguard: found %d modules\n", len(availableModules))
		modules.LoadAll(availableModules)
	}
	bootlog.Log(bootlog.EventModulesLoaded, "count", fmt.Sprintf("%d", len(availableModules)))
	tui.StageDone(tui.StageModules)

	// 8. Trigger udev events for firmware loading
	buildtags.Debug("vanguard: triggering udev events\n")
	udev.Trigger()
	udev.Settle(10 * time.Second)

	// 9. Load TPM modules explicitly before cryptsetup (only if needed)
	tui.UpdateStage(tui.StageTPM)
	loadTPMModulesIfNeeded()
	tui.StageDone(tui.StageTPM)

	// 10. Setup pcrlock (needed before LUKS unlock if using pcrlock policy)
	if earlyBootMounted {
		tui.UpdateStage(tui.StagePCRLock)
		buildtags.Debug("vanguard: setting up pcrlock early\n")
		if err := mount.SetupPCRLockEarly(); err != nil {
			buildtags.Debug("vanguard: early pcrlock setup: %v\n", err)
			bootlog.Log(bootlog.EventPCRLock, "found", "false", "error", err.Error())
		} else {
			bootlog.Log(bootlog.EventPCRLock, "found", "true")
		}
		tui.StageDone(tui.StagePCRLock)
		// NOTE: Do NOT unmount /boot here - keep mounted for logging
	}

	// 10a. Security check: if pcrlock is in use, verify PCR 7 (Secure Boot
	// state) is non-zero. An all-zeros PCR 7 means Secure Boot is off or
	// not measured by firmware, which means the initramfs could have been
	// replaced by an attacker with physical access. Refuse to unseal in
	// this case to prevent PIN capture by a rogue initramfs.
	// This is a software backstop — the real protection is Secure Boot + UKI.
	pcrlockActive := false
	if _, err := os.Stat("/var/lib/systemd/pcrlock.json"); err == nil {
		pcrlockActive = true
	}
	if _, err := os.Stat("/run/systemd/pcrlock.json"); err == nil {
		pcrlockActive = true
	}
	if pcrlockActive {
		tpmClient := intpm.New()
		if tpmClient.WaitForDevice(2 * time.Second) {
			pcr7, err := tpmClient.ReadPCR(intpm.AlgSHA256, 7)
			if err != nil {
				// PCR 7 read failed — possible TPM interference. Refuse to
				// proceed: an attacker who can block PCR reads could bypass
				// the all-zeros check and reach the pcrlock unseal path.
				console.Print("vanguard: SECURITY: failed to read PCR 7: %v\n", err)
				console.Print("vanguard: SECURITY: refusing to unseal — PCR 7 verification unavailable\n")
				bootlog.Log(bootlog.EventDebug, "msg", fmt.Sprintf("PCR 7 read failed, refusing pcrlock unseal: %v", err))
				cleanupAndHalt()
			}
			allZeros := true
			for _, b := range pcr7 {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				console.Print("vanguard: SECURITY: PCR 7 is all-zeros — Secure Boot not measured\n")
				console.Print("vanguard: SECURITY: refusing to unseal pcrlock token without Secure Boot\n")
				bootlog.Log(bootlog.EventDebug, "msg", "PCR 7 all-zeros, refusing pcrlock unseal")
				cleanupAndHalt()
			}
		}
	}

	// 11. Unlock encrypted devices (required - halt if none found)
	tui.UpdateStage(tui.StageLUKS)
	buildtags.Debug("vanguard: unlocking encrypted devices\n")
	unlocked, err := initluks.UnlockDevices()
	if err != nil {
		tui.StageError(tui.StageLUKS, err)
		bootlog.Log(bootlog.EventLUKSFail, "error", err.Error())
		console.Print("vanguard: failed to unlock devices: %v\n", err)
		cleanupAndHalt()
	}
	if !unlocked {
		tui.StageError(tui.StageLUKS, fmt.Errorf("no LUKS devices found"))
		bootlog.Log(bootlog.EventLUKSFail, "error", "no LUKS devices found")
		console.Print("vanguard: no LUKS devices found\n")
		cleanupAndHalt()
	}
	tui.StageDone(tui.StageLUKS)
	// Note: Per-device LUKS_UNLOCK events are logged by cryptsetup package

	// 12. Scan and activate LVM
	tui.UpdateStage(tui.StageLVM)
	buildtags.Debug("vanguard: activating LVM volumes\n")
	if err := lvm.Activate(); err != nil {
		buildtags.Debug("vanguard: warning: LVM activation failed: %v\n", err)
		bootlog.Log(bootlog.EventLVMActivate, "status", "error", "error", err.Error())
	} else {
		bootlog.Log(bootlog.EventLVMActivate, "status", "ok")
	}
	tui.StageDone(tui.StageLVM)

	// 13. Try hibernate resume (swap is now accessible after LUKS+LVM)
	// This must happen BEFORE mounting root read-write
	tui.UpdateStage(tui.StageResume)
	buildtags.Debug("vanguard: checking for hibernate resume\n")
	if err := resume.TryResume(); err != nil {
		buildtags.Debug("vanguard: resume error: %v\n", err)
	}
	tui.StageDone(tui.StageResume)
	// If resume succeeded, we never reach this point (kernel takes over)

	// 14. Determine root device (cmdline -> fstab -> GPT autodiscovery)
	buildtags.Debug("vanguard: determining root device\n")
	rootDev, rootFSType, err := mount.GetRootDevice()
	if err != nil {
		// Try GPT autodiscovery as last resort
		if gpt.IsGPTAutoEnabled() {
			buildtags.Debug("vanguard: trying GPT autodiscovery\n")
			if discovered, discoverErr := gpt.DiscoverRootPartition(); discoverErr == nil {
				rootDev = discovered
				rootFSType = "" // Will be auto-detected
				err = nil
				bootlog.Log(bootlog.EventDebug, "msg", fmt.Sprintf("GPT autodiscovery found root: %s", rootDev))
			} else {
				buildtags.Debug("vanguard: GPT autodiscovery failed: %v\n", discoverErr)
			}
		}
	}
	if err != nil {
		bootlog.Log(bootlog.EventRootMounted, "status", "error", "error", "no root device found")
		console.Print("vanguard: failed to determine root device: %v\n", err)
		cleanupAndHalt()
	}

	// 15. Run fsck on root device before mounting
	if fsck.CheckEnabled() {
		tui.UpdateStage(tui.StageFsck)
		buildtags.Debug("vanguard: running fsck on %s\n", rootDev)
		if err := fsck.Check(rootDev, rootFSType); err != nil {
			bootlog.Log(bootlog.EventDebug, "msg", fmt.Sprintf("fsck error: %v", err))
			console.Print("vanguard: fsck failed on %s: %v\n", rootDev, err)
			// Don't halt - let mount attempt proceed, it may still work
		} else {
			bootlog.Log(bootlog.EventDebug, "msg", "fsck completed successfully")
		}
		tui.StageDone(tui.StageFsck)
	}

	// 16. Mount real root filesystem
	tui.UpdateStage(tui.StageRoot)
	buildtags.Debug("vanguard: mounting root filesystem\n")
	if err := mount.RootWithDevice("/sysroot", rootDev, rootFSType); err != nil {
		tui.StageError(tui.StageRoot, err)
		bootlog.Log(bootlog.EventRootMounted, "status", "error", "error", err.Error())
		console.Print("vanguard: failed to mount root: %v\n", err)
		cleanupAndHalt()
	}
	tui.StageDone(tui.StageRoot)
	bootlog.Log(bootlog.EventRootMounted, "target", "/sysroot", "device", rootDev, "status", "ok")

	// 16a. Mount non-root filesystems from fstab into /sysroot.
	// Since the devices already exist (LVM is active, symlinks are created),
	// mounting them now means systemd finds them already mounted after
	// switch_root and doesn't try to wait for device nodes from udev.
	buildtags.Debug("vanguard: mounting non-root filesystems from fstab\n")
	if err := mount.MountNonRootFromFstab("/sysroot"); err != nil {
		buildtags.Debug("vanguard: warning: non-root fstab mounts: %v\n", err)
	}

	// 16b. Create LVM symlinks in /sysroot/dev for persistence after switch_root
	buildtags.Debug("vanguard: creating LVM symlinks in sysroot\n")
	if err := lvm.CreateSymlinksForSysroot("/sysroot"); err != nil {
		buildtags.Debug("vanguard: warning: failed to create sysroot LVM symlinks: %v\n", err)
	}

	// 17. Cleanup udev before switch_root
	// Wait for all udev events to settle
	buildtags.Debug("vanguard: waiting for udev events to settle\n")
	udev.Settle(5 * time.Second)

	// Trigger graphics and DRM subsystems to ensure /dev/dri/card* has proper permissions
	// This is critical for Wayland compositors (Hyprland, sway, etc.) to work after boot
	buildtags.Debug("vanguard: triggering graphics and DRM subsystems\n")
	udev.TriggerGraphics()
	udev.Settle(2 * time.Second)

	// Clean up udev database - dm devices with db_persist flag will survive
	buildtags.Debug("vanguard: cleaning up udev database\n")
	if err := udev.CleanupDB(); err != nil {
		buildtags.Debug("vanguard: warning: udev cleanup: %v\n", err)
	}

	// Stop udevd gracefully
	buildtags.Debug("vanguard: stopping udevd\n")
	udev.Stop()

	// Ensure LVM symlinks exist in /dev before switch_root.
	// switch_root moves the entire initramfs /dev (devtmpfs) to /sysroot/dev
	// via MS_MOVE, so symlinks created here survive and are visible to the
	// real system. This is critical for systemd to find non-root LVs in fstab.
	buildtags.Debug("vanguard: ensuring LVM symlinks in /dev\n")
	if err := lvm.EnsureDevSymlinks(); err != nil {
		buildtags.Debug("vanguard: warning: LVM dev symlinks: %v\n", err)
	}

	// 18. Close boot log and unmount /boot before switchroot
	bootlog.Log(bootlog.EventSwitchroot, "target", "/sysroot")
	bootlog.Close()

	// In test mode: flush coverage data and exit instead of switchroot
	if testMode {
		console.Print("vanguard: test mode — flushing coverage data and exiting\n")
		// Sync filesystems to ensure coverage data is written
		unix.Sync()
		// os.Exit triggers Go runtime to flush coverage data to GOCOVERDIR
		os.Exit(0)
	}
	if earlyBootMounted {
		buildtags.Debug("vanguard: unmounting early /boot\n")
		if err := mount.UnmountBootEarly(); err != nil {
			console.Print("vanguard: warning: failed to unmount /boot: %v (continuing)\n", err)
		}
	}

	// CRITICAL: Stop TUI and reset TTY before switch_root
	// This releases DRM master lock and restores normal terminal state
	// The TUI uses alternate screen buffer which must be cleaned up before
	// exec() to new init, otherwise systemd inherits a broken terminal
	if tui.IsEnabled() {
		tui.Quit()
		tui.ForceReset()
	}

	// 19. Switch root to init
	buildtags.Debug("vanguard: switching root to /sysroot\n")
	initPaths := []string{
		"/usr/lib/systemd/systemd",
		"/lib/systemd/systemd",
		"/sbin/init",
		"/init",
	}

	for _, initPath := range initPaths {
		err := switchroot.SwitchRoot("/sysroot", initPath)
		if err != nil {
			buildtags.Debug("vanguard: %s: %v\n", initPath, err)
		}
		// If we get here, exec failed - try next
	}

	// Last resort: drop to a rescue shell if one is available on the root fs.
	// This allows manual recovery (mount, fsck, cryptsetup) instead of a
	// silent halt. Controlled by kernel cmdline 'vanguard.rescue=1' or
	// automatic when /bin/sh exists on the root filesystem.
	rescueShell := "/bin/sh"
	if _, err := os.Stat("/sysroot" + rescueShell); err == nil {
		console.Print("vanguard: no init found — dropping to rescue shell (%s)\n", rescueShell)
		console.Print("vanguard: type 'exit' to halt\n")
		bootlog.Close()
		if earlyBootMounted {
			mount.UnmountBootEarly()
		}
		if tui.IsEnabled() {
			tui.Quit()
			tui.ForceReset()
		}
		if err := switchroot.SwitchRoot("/sysroot", rescueShell); err != nil {
			console.Print("vanguard: rescue shell failed: %v\n", err)
		}
	}

	console.Print("vanguard: no init found on root filesystem\n")
	cleanupAndHalt()
}

// discoverModules scans /lib/modules for available kernel modules in the image
func discoverModules() []string {
	var mods []string

	// Check if /lib/modules exists before walking
	if _, err := os.Stat("/lib/modules"); os.IsNotExist(err) {
		return mods
	}

	filepath.Walk("/lib/modules", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			buildtags.Debug("vanguard: module discovery error at %s: %v\n", path, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		name := info.Name()
		if strings.HasSuffix(name, ".ko") ||
			strings.HasSuffix(name, ".ko.gz") ||
			strings.HasSuffix(name, ".ko.xz") ||
			strings.HasSuffix(name, ".ko.zst") {
			modName := name
			for ext := filepath.Ext(modName); ext != ""; ext = filepath.Ext(modName) {
				modName = strings.TrimSuffix(modName, ext)
			}
			mods = append(mods, modName)
		}
		return nil
	})

	return mods
}

func halt() {
	if isTestMode() {
		console.Print("vanguard: test mode — flushing coverage data\n")
		// os.Exit(0) triggers Go's coverage flush (writes .cov files to GOCOVERDIR).
		// The kernel will panic ("Attempted to kill init!") but the coverage
		// files are written synchronously before the exit syscall returns.
		// The kernel panic happens AFTER the process exits, so the files
		// should already be on the FAT disk.
		// We call unix.Sync() first to flush any pending FAT metadata writes.
		unix.Sync()
		os.Exit(0)
	}
	console.Print("vanguard: system halted\n")
	console.Print("vanguard: press Ctrl+Alt+Del to reboot\n")
	for {
		time.Sleep(time.Hour)
	}
}

// cleanupAndHalt performs cleanup (close bootlog, unmount /boot, reset TUI)
// before halting. This ensures diagnostics are flushed to disk and the
// terminal is restored on every failure path, not just the success path.
func cleanupAndHalt() {
	bootlog.Close()
	if earlyBootMounted {
		if err := mount.UnmountBootEarly(); err != nil {
			console.Print("vanguard: warning: failed to unmount /boot: %v\n", err)
		}
	}
	if tui.IsEnabled() {
		tui.Quit()
		tui.ForceReset()
	}
	halt()
}

// loadTPMModulesIfNeeded loads TPM driver modules if TPM device doesn't exist
// and modules are available in the initramfs. Skips silently if modules aren't
// included or TPM is already available (e.g., built into kernel or loaded by udev).
func loadTPMModulesIfNeeded() {
	// Check if TPM device already exists (module already loaded or built-in)
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		buildtags.Debug("vanguard: TPM device already available, skipping module load\n")
		return
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		buildtags.Debug("vanguard: TPM device already available, skipping module load\n")
		return
	}

	// Check if modules are available in the initramfs
	if _, err := os.Stat("/lib/modules"); os.IsNotExist(err) {
		buildtags.Debug("vanguard: /lib/modules not found, skipping TPM module load\n")
		return
	}

	// Try to load TPM driver modules
	buildtags.Debug("vanguard: loading TPM modules\n")
	tpmModules := []string{"tpm_crb", "tpm_tis", "tpm_tis_core"}
	for _, mod := range tpmModules {
		if err := modules.LoadByName(mod); err != nil {
			// Only log debug, don't print errors for modules not in initramfs
			buildtags.Debug("vanguard: tpm module %s not loaded: %v\n", mod, err)
		} else {
			buildtags.Debug("vanguard: tpm module %s loaded\n", mod)
		}
	}
}

// isTestMode checks the kernel command line for vanguard.testmode=1.
func isTestMode() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "vanguard.testmode=1")
}

// mountTestCoverDisk mounts a FAT-formatted virtio-blk disk for Go coverage
// data export. Scans /dev for the cover disk (vda, vdb, sda, sdb).
func mountTestCoverDisk() error {
	// If /cover is already mounted (by the C wrapper), just set GOCOVERDIR
	if mount.IsMounted("/cover") {
		os.Setenv("GOCOVERDIR", "/cover")
		console.Print("vanguard: cover disk already mounted at /cover\n")
		return nil
	}

	// Try common device names for the cover disk
	// virtio-blk-pci shows up as /dev/vda, /dev/vdb, etc.
	// The test disk is on virtio-scsi, so virtio-blk should be /dev/vda
	candidates := []string{"/dev/vda", "/dev/vdb", "/dev/sda", "/dev/sdb"}

	// Wait for devtmpfs to populate (up to 3 seconds)
	var coverDev string
	for attempt := 0; attempt < 30; attempt++ {
		for _, dev := range candidates {
			if _, err := os.Stat(dev); err == nil {
				// Skip the root disk - check if it's already the LUKS disk
				// by reading the first few bytes (LUKS magic)
				f, err := os.Open(dev)
				if err != nil {
					continue
				}
				magic := make([]byte, 6)
				f.Read(magic)
				f.Close()
				if string(magic[:4]) == "LUKS" {
					continue // This is the LUKS disk, not the cover disk
				}
				coverDev = dev
				break
			}
		}
		if coverDev != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if coverDev == "" {
		console.Print("vanguard: no cover disk found after waiting\n")
		return nil
	}

	// Create mount point on rootfs (initramfs tmpfs, always writable)
	if err := os.MkdirAll("/cover", 0755); err != nil {
		return fmt.Errorf("mkdir /cover: %w", err)
	}

	// Mount as vfat (read-write)
	if err := unix.Mount(coverDev, "/cover", "vfat", 0, ""); err != nil {
		return fmt.Errorf("mount %s: %w", coverDev, err)
	}

	// Set GOCOVERDIR so Go runtime writes coverage data here
	os.Setenv("GOCOVERDIR", "/cover")
	console.Print("vanguard: cover disk mounted at /cover (%s)\n", coverDev)

	return nil
}
