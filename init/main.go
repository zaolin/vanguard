package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zaolin/vanguard/init/bootlog"
	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/init/cryptsetup"
	"github.com/zaolin/vanguard/init/fsck"
	"github.com/zaolin/vanguard/init/gpt"
	"github.com/zaolin/vanguard/init/lvm"
	"github.com/zaolin/vanguard/init/modules"
	"github.com/zaolin/vanguard/init/mount"
	"github.com/zaolin/vanguard/init/resume"
	"github.com/zaolin/vanguard/init/switchroot"
	"github.com/zaolin/vanguard/init/tui"
	"github.com/zaolin/vanguard/init/udev"
	"github.com/zaolin/vanguard/init/vconsole"
)

func main() {
	// 1. Setup early console for debugging and passphrase prompts
	if err := console.Setup(); err != nil {
		os.Exit(1)
	}

	// Suppress kernel messages (dmesg) on console to avoid cluttering output
	console.SuppressKernelMessages()

	// Enable debug output in console package based on build tag
	console.DebugEnabled = debugEnabled

	debug("vanguard: starting init\n")

	// Pass debug function to packages
	cryptsetup.Debug = debug
	vconsole.Debug = debug
	resume.Debug = debug
	fsck.Debug = debug
	gpt.Debug = debug

	// Pass boot logging function to cryptsetup package
	cryptsetup.LogFunc = func(event string, kvPairs ...string) {
		bootlog.Log(bootlog.Event(event), kvPairs...)
	}

	// 2. Mount essential filesystems
	debug("vanguard: mounting filesystems\n")
	if err := mount.Essential(); err != nil {
		console.Print("vanguard: failed to mount filesystems: %v\n", err)
		halt()
	}

	// 3. Configure vconsole (keymap + font) BEFORE any password prompts
	debug("vanguard: configuring vconsole\n")
	if err := vconsole.Configure(); err != nil {
		debug("vanguard: vconsole configuration: %v\n", err)
	}

	// Start TUI in non-debug mode (no-op in debug mode)
	if tui.IsEnabled() {
		if err := tui.Start(); err != nil {
			debug("vanguard: TUI start failed: %v\n", err)
		}
		defer tui.Quit()
	}

	// 4. Mount /boot early for logging (before anything else)
	debug("vanguard: mounting /boot early\n")
	earlyBootMounted, err := mount.MountBootEarly()
	if err != nil {
		debug("vanguard: early mount /boot: %v\n", err)
	}

	// 5. Initialize boot log immediately after /boot is mounted
	if earlyBootMounted {
		if err := bootlog.Init(); err != nil {
			debug("vanguard: bootlog init: %v\n", err)
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
	debug("vanguard: starting udevd\n")
	if err := udev.Start(); err != nil {
		debug("vanguard: udevd start warning: %v\n", err)
	}
	tui.StageDone(tui.StageUdev)

	// 7. Load kernel modules (only those available in the image)
	tui.UpdateStage(tui.StageModules)
	debug("vanguard: loading kernel modules\n")
	availableModules := discoverModules()
	if len(availableModules) > 0 {
		debug("vanguard: found %d modules\n", len(availableModules))
		modules.LoadAll(availableModules)
	}
	bootlog.Log(bootlog.EventModulesLoaded, "count", fmt.Sprintf("%d", len(availableModules)))
	tui.StageDone(tui.StageModules)

	// 8. Trigger udev events for firmware loading
	debug("vanguard: triggering udev events\n")
	udev.Trigger()
	udev.Settle(10 * time.Second)

	// 9. Load TPM modules explicitly before cryptsetup
	tui.UpdateStage(tui.StageTPM)
	debug("vanguard: loading TPM modules\n")
	tpmModules := []string{"tpm_crb", "tpm_tis", "tpm_tis_core"}
	for _, mod := range tpmModules {
		if err := modules.LoadByName(mod); err != nil {
			debug("vanguard: tpm module %s: %v\n", mod, err)
		}
	}
	tui.StageDone(tui.StageTPM)

	// 10. Setup pcrlock (needed before LUKS unlock if using pcrlock policy)
	if earlyBootMounted {
		tui.UpdateStage(tui.StagePCRLock)
		debug("vanguard: setting up pcrlock early\n")
		if err := mount.SetupPCRLockEarly(); err != nil {
			debug("vanguard: early pcrlock setup: %v\n", err)
			bootlog.Log(bootlog.EventPCRLock, "found", "false", "error", err.Error())
		} else {
			bootlog.Log(bootlog.EventPCRLock, "found", "true")
		}
		tui.StageDone(tui.StagePCRLock)
		// NOTE: Do NOT unmount /boot here - keep mounted for logging
	}

	// 11. Unlock encrypted devices (required - halt if none found)
	tui.UpdateStage(tui.StageLUKS)
	debug("vanguard: unlocking encrypted devices\n")
	unlocked, err := cryptsetup.UnlockDevices()
	if err != nil {
		tui.StageError(tui.StageLUKS, err)
		bootlog.Log(bootlog.EventLUKSFail, "error", err.Error())
		console.Print("vanguard: failed to unlock devices: %v\n", err)
		bootlog.Close()
		halt()
	}
	if !unlocked {
		tui.StageError(tui.StageLUKS, fmt.Errorf("no LUKS devices found"))
		bootlog.Log(bootlog.EventLUKSFail, "error", "no LUKS devices found")
		console.Print("vanguard: no LUKS devices found\n")
		bootlog.Close()
		halt()
	}
	tui.StageDone(tui.StageLUKS)
	// Note: Per-device LUKS_UNLOCK events are logged by cryptsetup package

	// 11a. Trigger udev to process dm-crypt device (for db_persist)
	// Since we use DM_DISABLE_UDEV=1, we need to manually trigger udev
	debug("vanguard: triggering udev for dm-crypt devices\n")
	udev.Trigger()
	udev.Settle(5 * time.Second)

	// 12. Scan and activate LVM
	tui.UpdateStage(tui.StageLVM)
	debug("vanguard: activating LVM volumes\n")
	if err := lvm.Activate(); err != nil {
		debug("vanguard: warning: LVM activation failed: %v\n", err)
		bootlog.Log(bootlog.EventLVMActivate, "status", "error", "error", err.Error())
	} else {
		bootlog.Log(bootlog.EventLVMActivate, "status", "ok")
	}
	tui.StageDone(tui.StageLVM)

	// 12a. Trigger udev to process LVM devices (for db_persist)
	debug("vanguard: triggering udev for LVM devices\n")
	udev.Trigger()
	udev.Settle(5 * time.Second)

	// 13. Try hibernate resume (swap is now accessible after LUKS+LVM)
	// This must happen BEFORE mounting root read-write
	tui.UpdateStage(tui.StageResume)
	debug("vanguard: checking for hibernate resume\n")
	if err := resume.TryResume(); err != nil {
		debug("vanguard: resume error: %v\n", err)
	}
	tui.StageDone(tui.StageResume)
	// If resume succeeded, we never reach this point (kernel takes over)

	// 14. Determine root device (cmdline -> fstab -> GPT autodiscovery)
	debug("vanguard: determining root device\n")
	rootDev, rootFSType, err := mount.GetRootDevice()
	if err != nil {
		// Try GPT autodiscovery as last resort
		if gpt.IsGPTAutoEnabled() {
			debug("vanguard: trying GPT autodiscovery\n")
			if discovered, discoverErr := gpt.DiscoverRootPartition(); discoverErr == nil {
				rootDev = discovered
				rootFSType = "" // Will be auto-detected
				err = nil
				bootlog.Log(bootlog.EventDebug, "msg", fmt.Sprintf("GPT autodiscovery found root: %s", rootDev))
			}
		}
	}
	if err != nil {
		bootlog.Log(bootlog.EventRootMounted, "status", "error", "error", "no root device found")
		console.Print("vanguard: failed to determine root device: %v\n", err)
		bootlog.Close()
		halt()
	}

	// 15. Run fsck on root device before mounting
	if fsck.CheckEnabled() {
		tui.UpdateStage(tui.StageFsck)
		debug("vanguard: running fsck on %s\n", rootDev)
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
	debug("vanguard: mounting root filesystem\n")
	if err := mount.RootWithDevice("/sysroot", rootDev, rootFSType); err != nil {
		tui.StageError(tui.StageRoot, err)
		bootlog.Log(bootlog.EventRootMounted, "status", "error", "error", err.Error())
		console.Print("vanguard: failed to mount root: %v\n", err)
		bootlog.Close()
		halt()
	}
	tui.StageDone(tui.StageRoot)
	bootlog.Log(bootlog.EventRootMounted, "target", "/sysroot", "device", rootDev, "status", "ok")

	// 16a. Create LVM symlinks in /sysroot/dev for persistence after switch_root
	debug("vanguard: creating LVM symlinks in sysroot\n")
	if err := lvm.CreateSymlinksForSysroot("/sysroot"); err != nil {
		debug("vanguard: warning: failed to create sysroot LVM symlinks: %v\n", err)
	}

	// 17. Cleanup udev before switch_root
	// Wait for all udev events to settle
	debug("vanguard: waiting for udev events to settle\n")
	udev.Settle(5 * time.Second)

	// Clean up udev database - dm devices with db_persist flag will survive
	debug("vanguard: cleaning up udev database\n")
	if err := udev.CleanupDB(); err != nil {
		debug("vanguard: warning: udev cleanup: %v\n", err)
	}

	// Stop udevd gracefully
	debug("vanguard: stopping udevd\n")
	udev.Stop()

	// 18. Close boot log and unmount /boot before switchroot
	bootlog.Log(bootlog.EventSwitchroot, "target", "/sysroot")
	bootlog.Close()
	if earlyBootMounted {
		debug("vanguard: unmounting early /boot\n")
		if err := mount.UnmountBootEarly(); err != nil {
			debug("vanguard: early unmount /boot: %v\n", err)
		}
	}

	// 19. Switch root to init
	tui.UpdateStage(tui.StageSwitchroot)
	debug("vanguard: switching root to /sysroot\n")
	initPaths := []string{
		"/usr/lib/systemd/systemd",
		"/lib/systemd/systemd",
		"/sbin/init",
		"/init",
	}

	for _, initPath := range initPaths {
		err := switchroot.SwitchRoot("/sysroot", initPath)
		if err != nil {
			debug("vanguard: %s: %v\n", initPath, err)
		}
		// If we get here, exec failed - try next
	}

	console.Print("vanguard: no init found on root filesystem\n")
	halt()
}

// discoverModules scans /lib/modules for available kernel modules in the image
func discoverModules() []string {
	var mods []string

	filepath.Walk("/lib/modules", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
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
	console.Print("vanguard: system halted\n")
	console.Print("vanguard: press Ctrl+Alt+Del to reboot\n")
	for {
		time.Sleep(time.Hour)
	}
}
