package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zaolin/vanguard/cmd/vanguard/embed"
	"github.com/zaolin/vanguard/internal/compress"
	"github.com/zaolin/vanguard/internal/config"
	intcpio "github.com/zaolin/vanguard/internal/cpio"
	"github.com/zaolin/vanguard/internal/firmware"
	"github.com/zaolin/vanguard/internal/fstab"
	"github.com/zaolin/vanguard/internal/libs"
	"github.com/zaolin/vanguard/internal/luks"
	"github.com/zaolin/vanguard/internal/modules"
)

// Run executes the generate command
func (c *GenerateCmd) Run() error {
	// Load config file if specified
	cfg, err := config.Load(c.Config)
	if err != nil {
		return err
	}

	// Override config with CLI flags
	if c.Output != "" {
		cfg.Output = c.Output
	}
	if len(c.Firmware) > 0 {
		cfg.Firmware = c.Firmware
	}
	if len(c.Modules) > 0 {
		cfg.Modules = c.Modules
	}
	if c.Compression != "" {
		cfg.Compression = c.Compression
	}
	if c.Debug {
		cfg.Debug = true
	}
	if c.Strict {
		cfg.StrictMode = true
	}

	return runGenerate(cfg)
}

func runGenerate(cfg *config.Config) error {
	fmt.Printf("vanguard: generating initramfs\n")
	fmt.Printf("  output: %s\n", cfg.Output)
	fmt.Printf("  compression: %s\n", cfg.Compression)

	// Autodetect LUKS devices
	fmt.Printf("vanguard: detecting LUKS devices...\n")
	luksDevices, err := luks.Detect()
	if err != nil {
		fmt.Printf("  warning: failed to detect LUKS devices: %v\n", err)
	} else {
		fmt.Printf("  found %d LUKS device(s)\n", len(luksDevices))
		for _, dev := range luksDevices {
			fmt.Printf("    - %s (UUID: %s)\n", dev.Path, dev.UUID)
		}
	}

	// Parse fstab for root device
	fmt.Printf("vanguard: parsing /etc/fstab for root device...\n")
	rootDev, err := fstab.FindRoot()
	if err != nil {
		fmt.Printf("  warning: failed to parse fstab: %v\n", err)
	} else {
		fmt.Printf("  root device: %s\n", rootDev)
	}

	// Get embedded init binary based on configuration
	fmt.Printf("vanguard: using embedded init binary...\n")
	var initContent []byte
	switch {
	case cfg.Debug && cfg.StrictMode:
		initContent = embed.InitDebugStrictBinary
		fmt.Printf("  using debug+strict init (%d bytes)\n", len(initContent))
	case cfg.StrictMode:
		initContent = embed.InitStrictBinary
		fmt.Printf("  using strict init (%d bytes)\n", len(initContent))
	case cfg.Debug:
		initContent = embed.InitDebugBinary
		fmt.Printf("  using debug init (%d bytes)\n", len(initContent))
	default:
		initContent = embed.InitBinary
		fmt.Printf("  using release init (%d bytes)\n", len(initContent))
	}

	// Collect firmware files
	fmt.Printf("vanguard: collecting firmware files...\n")
	fwFiles, err := firmware.Collect(cfg.Firmware)
	if err != nil {
		return fmt.Errorf("failed to collect firmware: %w", err)
	}
	fmt.Printf("  collected %d firmware file(s)\n", len(fwFiles))

	// Create output file
	outFile, err := os.Create(cfg.Output)
	if err != nil {
		return fmt.Errorf("failed to create output: %w", err)
	}
	defer outFile.Close()

	// === EARLY FIRMWARE CPIO (uncompressed) ===
	// The kernel unpacks CPIO archives in sequence. An uncompressed early CPIO
	// is unpacked BEFORE do_basic_setup(), making firmware available to built-in
	// drivers that request firmware during kernel initialization.
	if len(fwFiles) > 0 {
		fmt.Printf("vanguard: creating early firmware CPIO (uncompressed)...\n")
		earlyArchive := intcpio.NewArchive(outFile)

		// Add firmware directory structure
		if err := earlyArchive.AddDirectory("lib", 0755); err != nil {
			return fmt.Errorf("failed to add lib directory: %w", err)
		}
		if err := earlyArchive.AddDirectory("lib/firmware", 0755); err != nil {
			return fmt.Errorf("failed to add lib/firmware directory: %w", err)
		}

		// Track directories we've created
		fwDirs := make(map[string]bool)
		fwDirs["lib"] = true
		fwDirs["lib/firmware"] = true

		// Add firmware files to early CPIO
		for _, fw := range fwFiles {
			dstPath := fw.DstPath[1:] // Remove leading /

			// Create parent directories
			dir := filepath.Dir(dstPath)
			for dir != "." && !fwDirs[dir] {
				// Need to create parent dirs first, collect them
				var dirsToCreate []string
				for d := dir; d != "." && !fwDirs[d]; d = filepath.Dir(d) {
					dirsToCreate = append([]string{d}, dirsToCreate...)
				}
				for _, d := range dirsToCreate {
					if err := earlyArchive.AddDirectory(d, 0755); err != nil {
						fmt.Printf("  warning: failed to add directory %s: %v\n", d, err)
					}
					fwDirs[d] = true
				}
				break
			}

			content, err := fw.Read()
			if err != nil {
				fmt.Printf("  warning: failed to read firmware %s: %v\n", fw.SrcPath, err)
				continue
			}
			if err := earlyArchive.AddFile(dstPath, content, 0644); err != nil {
				fmt.Printf("  warning: failed to add firmware %s: %v\n", fw.SrcPath, err)
				continue
			}
			fmt.Printf("  early: %s -> /%s (%d bytes)\n", fw.SrcPath, dstPath, len(content))
		}

		if err := earlyArchive.Close(); err != nil {
			return fmt.Errorf("failed to close early archive: %w", err)
		}
		fmt.Printf("  early firmware CPIO written\n")
	}

	// Collect kernel modules (only from CLI/config input)
	fmt.Printf("vanguard: collecting kernel modules...\n")
	modFiles, err := modules.Collect(cfg.Modules, "")
	if err != nil {
		fmt.Printf("  warning: failed to collect modules: %v\n", err)
	} else {
		fmt.Printf("  collected %d module(s)\n", len(modFiles))
	}

	// Resolve library dependencies for required binaries
	fmt.Printf("vanguard: resolving library dependencies...\n")

	// Find binaries - search multiple paths for each
	binarySearchPaths := map[string][]string{
		"cryptsetup":     {"/usr/bin/cryptsetup", "/usr/sbin/cryptsetup", "/sbin/cryptsetup", "/bin/cryptsetup"},
		"lvm":            {"/usr/sbin/lvm", "/sbin/lvm"},
		"dmsetup":        {"/sbin/dmsetup", "/usr/sbin/dmsetup", "/usr/bin/dmsetup"}, // Required by udev dm rules at /sbin/dmsetup
		"systemd-udevd":  {"/usr/lib/systemd/systemd-udevd", "/lib/systemd/systemd-udevd", "/sbin/udevd"},
		"udevadm":        {"/usr/bin/udevadm", "/sbin/udevadm", "/bin/udevadm"},
		"tpm2_pcrread":   {"/usr/bin/tpm2_pcrread", "/bin/tpm2_pcrread"},     // For TPM PCR debug output
		"tpm2_pcrextend": {"/usr/bin/tpm2_pcrextend", "/bin/tpm2_pcrextend"}, // For extending PCRs (e.g. LUKS header)
		// Vconsole support
		"loadkeys": {"/usr/bin/loadkeys", "/bin/loadkeys"}, // For keyboard layout
		"setfont":  {"/usr/bin/setfont", "/bin/setfont"},   // For console font
		// Filesystem check support
		"fsck":      {"/usr/bin/fsck", "/sbin/fsck"},                                              // Generic fsck wrapper
		"fsck.ext4": {"/usr/bin/fsck.ext4", "/sbin/fsck.ext4", "/usr/bin/e2fsck", "/sbin/e2fsck"}, // ext4 fsck
	}

	var requiredBinaries []string
	for name, paths := range binarySearchPaths {
		found := false
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				requiredBinaries = append(requiredBinaries, p)
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("  warning: %s not found in any standard path\n", name)
		}
	}

	var allLibs []libs.LibraryFile
	for _, bin := range requiredBinaries {
		binLibs, err := libs.ResolveDependencies(bin)
		if err != nil {
			fmt.Printf("  warning: failed to resolve deps for %s: %v\n", bin, err)
			continue
		}
		allLibs = append(allLibs, binLibs...)
	}

	// Add dlopen libraries (TPM2 token handler)
	dlopenLibs, _ := libs.ResolveDlopenDependencies()
	allLibs = append(allLibs, dlopenLibs...)
	fmt.Printf("  resolved %d libraries\n", len(allLibs))

	// === MAIN CPIO (compressed) ===
	// This is appended after the early firmware CPIO. The kernel unpacks
	// all CPIO archives in sequence, overlaying them on the rootfs.
	fmt.Printf("vanguard: creating main CPIO (%s compressed)...\n", cfg.Compression)

	// Create compression writer
	compWriter, err := compress.NewWriter(outFile, cfg.Compression)
	if err != nil {
		return fmt.Errorf("failed to create compressor: %w", err)
	}

	// Create CPIO archive
	archive := intcpio.NewArchive(compWriter)

	// Add directory structure
	dirs := []string{
		"bin", "sbin", "lib", "lib64", "lib/firmware",
		"dev", "proc", "sys", "run", "sysroot", "etc",
		"usr", "usr/bin", "usr/sbin", "usr/lib", "usr/lib64",
		"usr/lib64/cryptsetup", "var", "var/lib", "var/lib/systemd",
		"run/udev", "run/udev/data", "run/udev/tags",
		"usr/lib/udev", "usr/lib/udev/rules.d",
		"usr/lib/systemd",
	}
	for _, dir := range dirs {
		if err := archive.AddDirectory(dir, 0755); err != nil {
			return fmt.Errorf("failed to add directory %s: %w", dir, err)
		}
	}

	// Add symlink from /usr/lib/firmware to /lib/firmware
	// The kernel may search either path depending on configuration
	if err := archive.AddSymlink("usr/lib/firmware", "../../lib/firmware"); err != nil {
		fmt.Printf("  warning: failed to add /usr/lib/firmware symlink: %v\n", err)
	}

	// Add the dynamic linker - search common paths
	ldPaths := []string{
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/ld-linux-x86-64.so.2",
		"/usr/lib64/ld-linux-x86-64.so.2",
		"/usr/lib/ld-linux-x86-64.so.2",
	}
	for _, ldPath := range ldPaths {
		if _, err := os.Stat(ldPath); err == nil {
			// Resolve symlink to get the actual file
			realPath, err := filepath.EvalSymlinks(ldPath)
			if err != nil {
				realPath = ldPath
			}
			// Add the actual file
			dstPath := realPath[1:] // Remove leading /
			if err := archive.AddFileFromDisk(realPath, dstPath); err != nil {
				fmt.Printf("  warning: failed to add ld-linux: %v\n", err)
			} else {
				fmt.Printf("  added dynamic linker: %s\n", realPath)
			}
			// Add symlink if the paths differ
			if realPath != ldPath {
				symlinkDst := ldPath[1:] // Remove leading /
				archive.AddSymlink(symlinkDst, realPath)
			}
			break
		}
	}

	// Add init binary
	if err := archive.AddFile("init", initContent, 0755); err != nil {
		return fmt.Errorf("failed to add init: %w", err)
	}

	// Add required binaries
	for _, bin := range requiredBinaries {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		dstPath := bin[1:] // Remove leading /
		if err := archive.AddFileFromDisk(bin, dstPath); err != nil {
			fmt.Printf("  warning: failed to add %s: %v\n", bin, err)
		}
	}

	// Add LVM symlinks
	lvmSymlinks := map[string]string{
		"usr/sbin/pvscan":   "/usr/sbin/lvm",
		"usr/sbin/vgscan":   "/usr/sbin/lvm",
		"usr/sbin/lvscan":   "/usr/sbin/lvm",
		"usr/sbin/vgchange": "/usr/sbin/lvm",
		"usr/sbin/pvs":      "/usr/sbin/lvm",
		"usr/sbin/vgs":      "/usr/sbin/lvm",
		"usr/sbin/lvs":      "/usr/sbin/lvm",
	}
	for link, target := range lvmSymlinks {
		if err := archive.AddSymlink(link, target); err != nil {
			fmt.Printf("  warning: failed to add symlink %s: %v\n", link, err)
		}
	}

	// Ensure dmsetup is available at /sbin/dmsetup (udev rules hardcode this path)
	// If we found dmsetup elsewhere, add a symlink
	dmsetupPaths := []string{"/sbin/dmsetup", "/usr/sbin/dmsetup", "/usr/bin/dmsetup"}
	var foundDmsetup string
	for _, p := range dmsetupPaths {
		if _, err := os.Stat(p); err == nil {
			foundDmsetup = p
			break
		}
	}
	if foundDmsetup != "" && foundDmsetup != "/sbin/dmsetup" {
		// Add symlink from /sbin/dmsetup to where we found it
		if err := archive.AddSymlink("sbin/dmsetup", foundDmsetup); err != nil {
			fmt.Printf("  warning: failed to add dmsetup symlink: %v\n", err)
		}
	}

	// Add libraries
	seen := make(map[string]bool)
	for _, lib := range allLibs {
		if seen[lib.DstPath] {
			continue
		}
		seen[lib.DstPath] = true
		dstPath := lib.DstPath
		if dstPath[0] == '/' {
			dstPath = dstPath[1:]
		}
		if err := archive.AddFileFromDisk(lib.SrcPath, dstPath); err != nil {
			fmt.Printf("  warning: failed to add library %s: %v\n", lib.SrcPath, err)
		}
	}

	// NOTE: Firmware files are added to the early CPIO (uncompressed) above,
	// not here in the main CPIO. This allows built-in kernel drivers to load
	// firmware during kernel initialization before userspace starts.

	// Add kernel modules
	for _, mod := range modFiles {
		dstPath := mod.DstPath[1:] // Remove leading /
		// Create parent directories for modules
		modDir := filepath.Dir(dstPath)
		if !seen[modDir] {
			seen[modDir] = true
			archive.AddDirectory(modDir, 0755)
		}
		if err := archive.AddFileFromDisk(mod.SrcPath, dstPath); err != nil {
			fmt.Printf("  warning: failed to add module %s: %v\n", mod.SrcPath, err)
		}
	}

	// Add essential udev rules for device management and firmware loading
	fmt.Printf("vanguard: adding udev rules...\n")
	udevRulesDirs := []string{
		"/usr/lib/udev/rules.d",
		"/lib/udev/rules.d",
	}
	// Minimal set of udev rules for device-mapper support.
	// We only include rules that:
	// 1. Are required for dm device creation and db_persist
	// 2. Don't call external programs we don't have (ata_id, scsi_id, systemd-sysctl, etc.)
	essentialRules := []string{
		"10-dm.rules",        // Core device-mapper rules (uses dmsetup - we have it)
		"11-dm-lvm.rules",    // LVM symlinks in /dev/<vg>/<lv> (uses dmsetup splitname)
		"13-dm-disk.rules",   // DM disk symlinks (no external programs)
		"95-dm-notify.rules", // CRITICAL: calls dmsetup udevcomplete to signal completion
		// NOTE: The following are intentionally NOT included:
		// - 50-udev-default.rules: not needed for dm
		// - 60-persistent-storage.rules: calls ata_id, scsi_id we don't have
		// - 63-md-raid-arrays.rules: not needed
		// - 64-btrfs.rules: not needed
		// - 69-dm-lvm.rules: uses systemd-run we don't have
		// - 80-drivers.rules: uses kmod builtin, may cause issues
		// - 99-systemd.rules: calls systemd-sysctl we don't have
	}
	rulesAdded := 0
	for _, ruleDir := range udevRulesDirs {
		for _, rule := range essentialRules {
			srcPath := filepath.Join(ruleDir, rule)
			if _, err := os.Stat(srcPath); err == nil {
				dstPath := filepath.Join("usr/lib/udev/rules.d", rule)
				if !seen[dstPath] {
					seen[dstPath] = true
					if err := archive.AddFileFromDisk(srcPath, dstPath); err != nil {
						fmt.Printf("  warning: failed to add rule %s: %v\n", rule, err)
					} else {
						rulesAdded++
					}
				}
			}
		}
	}

	// Add custom rule for db_persist on dm devices (like dracut does)
	// This ensures dm devices survive udevadm info --cleanup-db before switch_root
	dbPersistRule := `# vanguard: mark dm devices with db_persist for switch_root survival
SUBSYSTEM!="block", GOTO="dm_persist_end"
KERNEL!="dm-[0-9]*", GOTO="dm_persist_end"
ACTION!="add|change", GOTO="dm_persist_end"
OPTIONS+="db_persist"
LABEL="dm_persist_end"
`
	if err := archive.AddFile("usr/lib/udev/rules.d/09-dm-persist.rules", []byte(dbPersistRule), 0644); err != nil {
		fmt.Printf("  warning: failed to add db_persist rule: %v\n", err)
	} else {
		rulesAdded++
	}

	fmt.Printf("  added %d udev rules\n", rulesAdded)

	// Add udev hwdb (optional but helpful)
	hwdbPaths := []string{"/usr/lib/udev/hwdb.bin", "/lib/udev/hwdb.bin"}
	for _, hwdb := range hwdbPaths {
		if _, err := os.Stat(hwdb); err == nil {
			dstPath := "usr/lib/udev/hwdb.bin"
			if err := archive.AddFileFromDisk(hwdb, dstPath); err != nil {
				fmt.Printf("  warning: failed to add hwdb: %v\n", err)
			} else {
				fmt.Printf("  added udev hwdb\n")
			}
			break
		}
	}

	// Add /etc/fstab for root device detection
	fmt.Printf("vanguard: adding /etc/fstab...\n")
	if err := archive.AddFileFromDisk("/etc/fstab", "etc/fstab"); err != nil {
		fmt.Printf("  warning: failed to add /etc/fstab: %v\n", err)
	}

	// Add /etc/vconsole.conf for keyboard layout and font configuration
	if _, err := os.Stat("/etc/vconsole.conf"); err == nil {
		fmt.Printf("vanguard: adding /etc/vconsole.conf...\n")
		if err := archive.AddFileFromDisk("/etc/vconsole.conf", "etc/vconsole.conf"); err != nil {
			fmt.Printf("  warning: failed to add /etc/vconsole.conf: %v\n", err)
		}
	}

	// Add essential device nodes
	if err := archive.AddDeviceNode("dev/console", 0600, 'c', 5, 1); err != nil {
		fmt.Printf("  warning: failed to add /dev/console: %v\n", err)
	}
	if err := archive.AddDeviceNode("dev/null", 0666, 'c', 1, 3); err != nil {
		fmt.Printf("  warning: failed to add /dev/null: %v\n", err)
	}
	if err := archive.AddDeviceNode("dev/zero", 0666, 'c', 1, 5); err != nil {
		fmt.Printf("  warning: failed to add /dev/zero: %v\n", err)
	}
	if err := archive.AddDeviceNode("dev/tty", 0666, 'c', 5, 0); err != nil {
		fmt.Printf("  warning: failed to add /dev/tty: %v\n", err)
	}

	// Close archive
	if err := archive.Close(); err != nil {
		return fmt.Errorf("failed to close archive: %w", err)
	}

	if err := compWriter.Close(); err != nil {
		return fmt.Errorf("failed to close compressor: %w", err)
	}

	// Get file size
	info, _ := os.Stat(cfg.Output)
	fmt.Printf("vanguard: generated %s (%d bytes)\n", cfg.Output, info.Size())

	return nil
}
