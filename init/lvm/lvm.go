package lvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zaolin/vanguard/init/console"
)

// LVM binary paths
var lvmPaths = []string{
	"/usr/sbin/lvm",
	"/sbin/lvm",
	"/usr/bin/lvm",
}

// findLVM finds the lvm binary
func findLVM() string {
	for _, path := range lvmPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// Activate scans for and activates all LVM volumes
func Activate() error {
	lvm := findLVM()
	if lvm == "" {
		console.Print("lvm: lvm binary not found, skipping\n")
		return nil
	}

	// Scan for physical volumes
	console.DebugPrint("lvm: scanning physical volumes\n")
	if err := runLVMVerbose(lvm, "pvscan", "--cache"); err != nil {
		console.DebugPrint("lvm: pvscan warning: %v\n", err)
	}

	// Scan for volume groups
	console.DebugPrint("lvm: scanning volume groups\n")
	if err := runLVMVerbose(lvm, "vgscan"); err != nil {
		console.DebugPrint("lvm: vgscan warning: %v\n", err)
	}

	// Activate all volume groups
	console.DebugPrint("lvm: activating volume groups\n")
	if err := runLVMVerbose(lvm, "vgchange", "-ay"); err != nil {
		console.DebugPrint("lvm: vgchange warning: %v\n", err)
	}

	// Create device nodes (needed without udev)
	console.DebugPrint("lvm: creating device nodes\n")
	runLVMVerbose(lvm, "vgmknodes")

	// Create /dev/<vg>/<lv> symlinks using lvs output for accuracy
	createVGSymlinksFromLVS(lvm)

	// Also try dmsetup if available
	dmsetupPaths := []string{"/usr/sbin/dmsetup", "/sbin/dmsetup"}
	for _, dmPath := range dmsetupPaths {
		if _, err := os.Stat(dmPath); err == nil {
			cmd := exec.Command(dmPath, "mknodes")
			cmd.Run()
			break
		}
	}

	// List what was activated with detailed info
	console.DebugPrint("lvm: listing activated volumes:\n")
	runLVMVerbose(lvm, "lvs", "-o", "vg_name,lv_name,lv_path,lv_dm_path,lv_attr")

	// Wait for device nodes to appear with retry logic
	waitForDevices(lvm)

	// Verify all volumes are accessible
	verifyVolumes()

	return nil
}

// runLVMVerbose executes an lvm subcommand and shows output.
// Note: We do NOT set DM_DISABLE_UDEV=1, so udev handles device creation
// and applies db_persist flag for dm devices to survive switch_root.
func runLVMVerbose(lvmPath string, subcmd string, args ...string) error {
	fullArgs := append([]string{subcmd}, args...)
	cmd := exec.Command(lvmPath, fullArgs...)
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		console.DebugPrint("lvm: %s\n", string(output))
	}
	return err
}

// runLVMOutput executes an lvm subcommand and returns output.
// Note: We do NOT set DM_DISABLE_UDEV=1, so udev handles device creation.
func runLVMOutput(lvmPath string, subcmd string, args ...string) (string, error) {
	fullArgs := append([]string{subcmd}, args...)
	cmd := exec.Command(lvmPath, fullArgs...)
	output, err := cmd.Output()
	return string(output), err
}

// waitForDevices waits for LVM device nodes to appear with retry logic
func waitForDevices(lvmPath string) {
	console.DebugPrint("lvm: waiting for device nodes...\n")

	var lastDevices string

	// Wait up to 10 seconds for devices to stabilize (increased from 5)
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)

		// Check /dev/mapper for LVM devices
		entries, err := filepath.Glob("/dev/mapper/*")
		if err != nil {
			continue
		}

		currentDevices := fmt.Sprintf("%v", entries)

		// Only print if devices changed
		if currentDevices != lastDevices {
			console.DebugPrint("lvm: found mapper devices: %v\n", entries)
			lastDevices = currentDevices
		}

		// Retry symlink creation periodically in case devices appeared late
		if i > 0 && i%4 == 0 {
			console.DebugPrint("lvm: retrying symlink creation...\n")
			createVGSymlinksFromLVS(lvmPath)
		}

		// If we have devices and they haven't changed for 2 iterations, we're done
		if len(entries) > 1 && currentDevices == lastDevices && i > 2 {
			console.DebugPrint("lvm: device nodes ready\n")
			return
		}
	}

	console.DebugPrint("lvm: timeout waiting for device nodes\n")
}

// createVGSymlinksFromLVS creates /dev/<vg>/<lv> symlinks using lvs output
// This is more reliable than parsing mapper names for VG/LV names with hyphens
func createVGSymlinksFromLVS(lvmPath string) {
	// Get VG, LV, and DM path from lvs
	output, err := runLVMOutput(lvmPath, "lvs", "--noheadings", "--separator", "|", "-o", "vg_name,lv_name,lv_dm_path")
	if err != nil {
		console.DebugPrint("lvm: failed to get lvs output: %v\n", err)
		// Fall back to mapper-based symlink creation
		createVGSymlinksFromMapper()
		return
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		vg := strings.TrimSpace(parts[0])
		lv := strings.TrimSpace(parts[1])
		dmPath := strings.TrimSpace(parts[2])

		if vg == "" || lv == "" || dmPath == "" {
			continue
		}

		// Create /dev/<vg> directory
		vgDir := filepath.Join("/dev", vg)
		if err := os.MkdirAll(vgDir, 0755); err != nil {
			console.DebugPrint("lvm: failed to create vg dir %s: %v\n", vgDir, err)
			continue
		}

		// Create symlink /dev/<vg>/<lv> -> <dmPath>
		lvPath := filepath.Join(vgDir, lv)
		if _, err := os.Lstat(lvPath); err == nil {
			// Already exists, verify it points to the right place
			target, err := os.Readlink(lvPath)
			if err == nil {
				console.DebugPrint("lvm: symlink %s already exists -> %s\n", lvPath, target)
			}
			continue
		}

		// Use relative symlink for portability
		relPath, err := filepath.Rel(vgDir, dmPath)
		if err != nil {
			relPath = dmPath // Fall back to absolute
		}

		if err := os.Symlink(relPath, lvPath); err != nil {
			console.DebugPrint("lvm: failed to create symlink %s: %v\n", lvPath, err)
		} else {
			console.DebugPrint("lvm: created symlink %s -> %s\n", lvPath, relPath)
		}
	}
}

// createVGSymlinksFromMapper creates /dev/<vg>/<lv> symlinks by parsing /dev/mapper names
// This is the fallback method when lvs is not available
func createVGSymlinksFromMapper() {
	entries, err := filepath.Glob("/dev/mapper/*")
	if err != nil {
		return
	}

	for _, mapperPath := range entries {
		name := filepath.Base(mapperPath)

		// Skip control device
		if name == "control" {
			continue
		}

		// LVM mapper names are <vg>-<lv>, but VG and LV names can contain hyphens
		// which are escaped as double hyphens (--) in the mapper name.
		idx := findVGLVSeparator(name)
		if idx == -1 {
			continue
		}

		vg := unescapeLVMName(name[:idx])
		lv := unescapeLVMName(name[idx+1:])

		// Create /dev/<vg> directory
		vgDir := filepath.Join("/dev", vg)
		if err := os.MkdirAll(vgDir, 0755); err != nil {
			continue
		}

		// Create symlink /dev/<vg>/<lv> -> /dev/mapper/<vg>-<lv>
		lvPath := filepath.Join(vgDir, lv)
		if _, err := os.Lstat(lvPath); err == nil {
			// Already exists
			continue
		}

		// Use relative symlink: ../mapper/<vg>-<lv>
		target := filepath.Join("../mapper", name)
		if err := os.Symlink(target, lvPath); err != nil {
			console.DebugPrint("lvm: failed to create symlink %s: %v\n", lvPath, err)
		} else {
			console.DebugPrint("lvm: created symlink %s -> %s\n", lvPath, target)
		}
	}
}

// verifyVolumes logs all accessible LVM volumes for debugging
func verifyVolumes() {
	console.DebugPrint("lvm: verifying volume accessibility...\n")

	// Check /dev/mapper devices
	mapperEntries, _ := filepath.Glob("/dev/mapper/*")
	for _, entry := range mapperEntries {
		name := filepath.Base(entry)
		if name == "control" {
			continue
		}
		info, err := os.Stat(entry)
		if err != nil {
			console.DebugPrint("lvm: /dev/mapper/%s - NOT ACCESSIBLE: %v\n", name, err)
		} else {
			console.DebugPrint("lvm: /dev/mapper/%s - OK (mode: %s)\n", name, info.Mode())
		}
	}

	// Check /dev/<vg>/* symlinks
	devEntries, _ := os.ReadDir("/dev")
	for _, entry := range devEntries {
		if !entry.IsDir() {
			continue
		}

		// Skip known special directories
		name := entry.Name()
		if isSpecialDevDir(name) {
			continue
		}

		vgDir := filepath.Join("/dev", name)
		lvEntries, err := os.ReadDir(vgDir)
		if err != nil {
			continue
		}

		if len(lvEntries) > 0 {
			console.DebugPrint("lvm: /dev/%s/ contains:\n", name)
			for _, lv := range lvEntries {
				lvPath := filepath.Join(vgDir, lv.Name())
				target, err := os.Readlink(lvPath)
				if err != nil {
					console.DebugPrint("lvm:   %s - not a symlink\n", lv.Name())
				} else {
					// Verify the target exists
					resolvedPath := filepath.Join(vgDir, target)
					if _, err := os.Stat(resolvedPath); err != nil {
						console.DebugPrint("lvm:   %s -> %s (BROKEN)\n", lv.Name(), target)
					} else {
						console.DebugPrint("lvm:   %s -> %s (OK)\n", lv.Name(), target)
					}
				}
			}
		}
	}
}

// isSpecialDevDir returns true if the directory name is a known special /dev subdirectory
func isSpecialDevDir(name string) bool {
	specialDirs := map[string]bool{
		"block":     true,
		"bus":       true,
		"char":      true,
		"cpu":       true,
		"disk":      true,
		"dri":       true,
		"hugepages": true,
		"input":     true,
		"mapper":    true, // We handle mapper separately
		"mqueue":    true,
		"net":       true,
		"pts":       true,
		"shm":       true,
		"snd":       true,
	}
	return specialDirs[name]
}

// findVGLVSeparator finds the index of the hyphen separating VG and LV names
// in a device-mapper name. Hyphens within VG/LV names are escaped as --.
func findVGLVSeparator(name string) int {
	// Replace -- with a placeholder to find single hyphens
	placeholder := "\x00"
	escaped := strings.ReplaceAll(name, "--", placeholder)

	idx := strings.Index(escaped, "-")
	if idx == -1 {
		return -1
	}

	// Convert index back accounting for replacements
	// Count how many placeholders appear before idx
	count := strings.Count(escaped[:idx], placeholder)
	return idx + count // Each -- became one char, so add back the difference
}

// unescapeLVMName converts escaped LVM names (-- -> -) back to original
func unescapeLVMName(name string) string {
	return strings.ReplaceAll(name, "--", "-")
}

// CreateSymlinksForSysroot creates /dev/<vg>/<lv> symlinks in the sysroot
// that will persist after switch_root. This is needed because symlinks created
// in the initramfs /dev are lost when switch_root replaces it with the real root's /dev.
func CreateSymlinksForSysroot(sysroot string) error {
	lvm := findLVM()
	if lvm == "" {
		return nil
	}

	output, err := runLVMOutput(lvm, "lvs", "--noheadings", "--separator", "|",
		"-o", "vg_name,lv_name,lv_dm_path")
	if err != nil {
		return err
	}

	devDir := filepath.Join(sysroot, "dev")

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		vg := strings.TrimSpace(parts[0])
		lv := strings.TrimSpace(parts[1])
		dmPath := strings.TrimSpace(parts[2])

		if vg == "" || lv == "" || dmPath == "" {
			continue
		}

		// Create /sysroot/dev/<vg> directory
		vgDir := filepath.Join(devDir, vg)
		if err := os.MkdirAll(vgDir, 0755); err != nil {
			console.DebugPrint("lvm: failed to create %s: %v\n", vgDir, err)
			continue
		}

		// Create symlink using absolute path to dm-X device
		// /dev/dm-X persists across switch_root since it's on devtmpfs
		lvPath := filepath.Join(vgDir, lv)
		dmDevice := filepath.Base(dmPath) // e.g., "dm-4"
		target := filepath.Join("/dev", dmDevice)

		// Skip if already exists
		if _, err := os.Lstat(lvPath); err == nil {
			console.DebugPrint("lvm: sysroot symlink %s already exists\n", lvPath)
			continue
		}

		if err := os.Symlink(target, lvPath); err != nil {
			console.DebugPrint("lvm: failed to create sysroot symlink %s: %v\n", lvPath, err)
		} else {
			console.DebugPrint("lvm: created sysroot symlink %s -> %s\n", lvPath, target)
		}
	}

	return nil
}
