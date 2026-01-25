package mount

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/init/fstab"
	"golang.org/x/sys/unix"
)

// Essential mounts the essential pseudo-filesystems needed for early boot
func Essential() error {
	// Stage 1: Mount essential filesystems first
	essentialMounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
		data   string
	}{
		{"proc", "/proc", "proc", 0, ""},
		{"sysfs", "/sys", "sysfs", 0, ""},
		{"devtmpfs", "/dev", "devtmpfs", 0, ""},
	}

	// Create mount points and mount essential filesystems
	for _, m := range essentialMounts {
		if err := os.MkdirAll(m.target, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", m.target, err)
		}
		if err := unix.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			return fmt.Errorf("mount %s on %s: %w", m.source, m.target, err)
		}
	}

	// Mount /run only if not already mounted
	if !IsMounted("/run") {
		if err := os.MkdirAll("/run", 0755); err != nil {
			return fmt.Errorf("mkdir /run: %w", err)
		}
		if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
			return fmt.Errorf("mount tmpfs on /run: %w", err)
		}
	}

	// Create essential device directories
	dirs := []string{"/dev/pts", "/dev/shm"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Stage 2: Mount optional filesystems (after sysfs is mounted)
	optionalMounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
	}{
		{"securityfs", "/sys/kernel/security", "securityfs", unix.MS_NOSUID | unix.MS_NODEV},
		{"efivarfs", "/sys/firmware/efi/efivars", "efivarfs", unix.MS_NOSUID | unix.MS_NODEV},
	}

	for _, m := range optionalMounts {
		// Create mount point (now safe since /sys is mounted)
		_ = os.MkdirAll(m.target, 0755)
		// Try to mount, ignore errors (these are optional)
		_ = unix.Mount(m.source, m.target, m.fstype, m.flags, "")
	}

	return nil
}

// Root mounts the root filesystem to the specified target
func Root(target string) error {
	// Get root device (tries fstab first, then kernel cmdline)
	rootDev, fstabFSType, err := getRootDevice()
	if err != nil {
		return fmt.Errorf("failed to determine root device: %w", err)
	}

	return RootWithDevice(target, rootDev, fstabFSType)
}

// RootWithDevice mounts the root filesystem with a specific device and filesystem type
// If fstype is empty, it will be auto-detected
func RootWithDevice(target, rootDev, fstype string) error {
	// Normalize LVM device paths (e.g., /dev/vg/lv -> /dev/mapper/vg-lv)
	rootDev = normalizeLVMPath(rootDev)

	console.DebugPrint("vanguard: root device: %s\n", rootDev)

	// Create mount point
	if err := os.MkdirAll(target, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", target, err)
	}

	// Detect filesystem type if not provided
	if fstype == "" {
		var err error
		fstype, err = detectFSType(rootDev)
		if err != nil {
			return fmt.Errorf("failed to detect filesystem type: %w", err)
		}
		console.DebugPrint("vanguard: detected filesystem type: %s\n", fstype)
	} else {
		console.DebugPrint("vanguard: filesystem type: %s\n", fstype)
	}

	// Mount root filesystem
	if err := unix.Mount(rootDev, target, fstype, 0, ""); err != nil {
		return fmt.Errorf("mount %s on %s: %w", rootDev, target, err)
	}

	return nil
}

// GetRootDevice determines the root device from kernel command line or fstab
// Returns device path, filesystem type (may be empty), and error
// Kernel cmdline root= parameter takes precedence over fstab
// This is exported for use by main.go to support GPT autodiscovery fallback
func GetRootDevice() (string, string, error) {
	return getRootDevice()
}

// getRootDevice determines the root device from kernel command line or fstab
// Returns device path, filesystem type (may be empty), and error
// Kernel cmdline root= parameter takes precedence over fstab
func getRootDevice() (string, string, error) {
	// Try kernel command line first (takes precedence)
	device, err := getRootFromCmdline()
	if err == nil && device != "" {
		console.DebugPrint("vanguard: found root in kernel cmdline: %s\n", device)
		// Try to get filesystem type from fstab for this device
		fstype := getFstabFSType(device)
		return device, fstype, nil
	}

	// Fall back to fstab
	console.DebugPrint("vanguard: root= not in cmdline, checking /etc/fstab\n")
	device, fstype, err := fstab.FindRoot("/etc/fstab")
	if err == nil && device != "" {
		console.DebugPrint("vanguard: found root in /etc/fstab: %s (type: %s)\n", device, fstype)
		return device, fstype, nil
	}

	return "", "", fmt.Errorf("root device not found in cmdline or fstab")
}

// getFstabFSType looks up the filesystem type for a device in fstab
// Returns empty string if not found
func getFstabFSType(device string) string {
	entries, err := fstab.Parse("/etc/fstab")
	if err != nil {
		return ""
	}

	// Normalize device path for comparison
	normalizedDev := normalizeLVMPath(device)

	for _, e := range entries {
		normalizedEntry := normalizeLVMPath(e.Device)
		if e.Device == device || normalizedEntry == normalizedDev ||
			e.Device == normalizedDev || normalizedEntry == device {
			return e.FSType
		}
	}
	return ""
}

// getRootFromCmdline parses the kernel command line for the root= parameter
func getRootFromCmdline() (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		if strings.HasPrefix(param, "root=") {
			return strings.TrimPrefix(param, "root="), nil
		}
	}

	return "", fmt.Errorf("root= parameter not found in kernel cmdline")
}

// detectFSType attempts to detect the filesystem type of a device
func detectFSType(device string) (string, error) {
	// Read the device to detect magic numbers
	f, err := os.Open(device)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 4096)
	if _, err := f.Read(buf); err != nil {
		return "", err
	}

	// Check for ext4 magic (0xEF53 at offset 0x438)
	if len(buf) > 0x43A && buf[0x438] == 0x53 && buf[0x439] == 0xEF {
		return "ext4", nil
	}

	// Check for XFS magic ("XFSB" at offset 0)
	if len(buf) >= 4 && string(buf[0:4]) == "XFSB" {
		return "xfs", nil
	}

	// Check for btrfs magic ("_BHRfS_M" at offset 0x10040)
	// This requires seeking, so try blkid fallback first

	// Fallback: try to read from /proc/mounts or use blkid
	return detectFSTypeBlkid(device)
}

// detectFSTypeBlkid uses blkid to detect filesystem type
func detectFSTypeBlkid(device string) (string, error) {
	// Read from /sys/class/block/.../device/../uevent or similar
	// For now, try common types
	commonTypes := []string{"ext4", "xfs", "btrfs"}

	// Create test mount directory
	os.MkdirAll("/tmp/.fstest", 0755)
	defer os.RemoveAll("/tmp/.fstest")

	for _, fstype := range commonTypes {
		// Try mounting with this type (will fail fast if wrong)
		if err := unix.Mount(device, "/tmp/.fstest", fstype, unix.MS_RDONLY, ""); err == nil {
			unix.Unmount("/tmp/.fstest", 0)
			return fstype, nil
		}
	}

	return "ext4", nil // Default to ext4
}

// MoveMount moves a mount from one location to another
func MoveMount(source, target string) error {
	return unix.Mount(source, target, "", unix.MS_MOVE, "")
}

// Unmount unmounts a filesystem
func Unmount(target string) error {
	return unix.Unmount(target, 0)
}

// IsMounted checks if a path is a mount point
func IsMounted(path string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}
	return false
}

// normalizeLVMPath converts LVM device paths from /dev/<vg>/<lv> format
// to /dev/mapper/<vg>-<lv> format, which is what LVM creates without udev.
// If the path is already in /dev/mapper/ format or doesn't look like an
// LVM path, it's returned unchanged.
func normalizeLVMPath(device string) string {
	// Already in /dev/mapper/ format
	if strings.HasPrefix(device, "/dev/mapper/") {
		return device
	}

	// Check if this looks like /dev/<vg>/<lv> format
	// It should be /dev/<something>/<something> but not a known special directory
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
		"disk":      true,
		"block":     true,
		"char":      true,
		"pts":       true,
		"shm":       true,
		"mqueue":    true,
		"hugepages": true,
		"net":       true,
		"bus":       true,
		"cpu":       true,
		"input":     true,
		"snd":       true,
		"dri":       true,
	}

	if specialDirs[vg] {
		return device
	}

	// Construct the /dev/mapper/<vg>-<lv> path
	mapperPath := filepath.Join("/dev/mapper", vg+"-"+lv)

	// Check if the mapper path exists
	if _, err := os.Stat(mapperPath); err == nil {
		console.DebugPrint("vanguard: normalized %s -> %s\n", device, mapperPath)
		return mapperPath
	}

	// If mapper path doesn't exist, check if original exists
	if _, err := os.Stat(device); err == nil {
		return device
	}

	// Neither exists, prefer the mapper path as LVM likely will create it there
	console.DebugPrint("vanguard: device %s not found, trying %s\n", device, mapperPath)
	return mapperPath
}

// MountBoot mounts /boot partition based on fstab entry
// Returns true if /boot was mounted, false if no /boot entry in fstab
func MountBoot(sysroot string) (bool, error) {
	bootPath := filepath.Join(sysroot, "boot")

	// Parse fstab to find /boot entry
	fstabPath := filepath.Join(sysroot, "etc/fstab")
	entries, err := fstab.Parse(fstabPath)
	if err != nil {
		return false, fmt.Errorf("parse fstab: %w", err)
	}

	var bootEntry *fstab.Entry
	for i, e := range entries {
		if e.Mountpoint == "/boot" {
			bootEntry = &entries[i]
			break
		}
	}

	if bootEntry == nil {
		// No /boot entry in fstab
		return false, nil
	}

	// Mount /boot
	if err := unix.Mount(bootEntry.Device, bootPath, bootEntry.FSType, 0, ""); err != nil {
		return false, fmt.Errorf("mount /boot: %w", err)
	}
	console.DebugPrint("vanguard: mounted /boot (%s)\n", bootEntry.Device)

	return true, nil
}

// UnmountBoot unmounts /boot partition
func UnmountBoot(sysroot string) error {
	bootPath := filepath.Join(sysroot, "boot")
	return unix.Unmount(bootPath, 0)
}

// SetupPCRLock copies pcrlock.json from /boot to the standard systemd path
// This assumes /boot is already mounted
func SetupPCRLock(sysroot string) error {
	src := filepath.Join(sysroot, "boot/pcrlock.json")
	dst := filepath.Join(sysroot, "var/lib/systemd/pcrlock.json")

	// Check if pcrlock.json exists
	if _, err := os.Stat(src); err != nil {
		// Not an error if pcrlock.json doesn't exist
		return nil
	}

	// Create destination directory
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("mkdir for pcrlock: %w", err)
	}

	// Copy the file
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read pcrlock.json: %w", err)
	}

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("write pcrlock.json: %w", err)
	}

	console.DebugPrint("vanguard: copied pcrlock.json to %s\n", dst)
	return nil
}

// MountBootEarly mounts /boot before root is available (for pcrlock.json access)
// It scans partitions to find one containing pcrlock.json or uses kernel cmdline boot= parameter
// Returns true if /boot was mounted, false if not found
func MountBootEarly() (bool, error) {
	// Create /boot mount point in initramfs
	if err := os.MkdirAll("/boot", 0755); err != nil {
		return false, fmt.Errorf("mkdir /boot: %w", err)
	}

	// Try to get boot device from kernel cmdline first
	bootDev := getBootFromCmdline()

	// If not specified, scan partitions to find one with pcrlock.json
	if bootDev == "" {
		bootDev = findBootPartition()
	}

	if bootDev == "" {
		return false, nil // No boot partition found
	}

	// Mount as vfat (ESP is always FAT32)
	if err := unix.Mount(bootDev, "/boot", "vfat", 0, ""); err != nil {
		return false, fmt.Errorf("failed to mount boot partition %s: %w", bootDev, err)
	}
	console.DebugPrint("vanguard: mounted early /boot (%s, vfat, rw)\n", bootDev)
	return true, nil
}

// UnmountBootEarly unmounts /boot in initramfs
func UnmountBootEarly() error {
	return unix.Unmount("/boot", 0)
}

// SetupPCRLockEarly copies pcrlock.json from /boot to /var/lib/systemd/ in initramfs
// This must be called before LUKS unlock when TPM2 token uses pcrlock policy
// It derives the pcrlock path from the booted UKI path via EFI variable
func SetupPCRLockEarly() error {
	dst := "/var/lib/systemd/pcrlock.json"

	// Get pcrlock path derived from booted UKI
	src := getPCRLockPath()
	if src == "" {
		// Not an error if no pcrlock.json exists
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(src); err != nil {
		console.DebugPrint("vanguard: pcrlock not found at %s\n", src)
		return nil
	}

	// Create destination directory
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("mkdir for pcrlock: %w", err)
	}

	// Copy the file
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read pcrlock.json: %w", err)
	}

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("write pcrlock.json: %w", err)
	}

	console.DebugPrint("vanguard: copied pcrlock.json to %s (early)\n", dst)
	return nil
}

// getPCRLockPath derives the pcrlock.json path from the booted UKI
// It reads the LoaderImageIdentifier EFI variable to get the UKI path,
// then replaces .efi with .pcrlock.json
// Returns empty string if UKI path cannot be determined
func getPCRLockPath() string {
	ukiPath := getBootedUKIPath()
	if ukiPath == "" {
		return ""
	}

	// Convert UKI path to pcrlock path: kernel.efi -> kernel.pcrlock.json
	pcrPath := strings.TrimSuffix(ukiPath, ".efi") + ".pcrlock.json"
	console.DebugPrint("vanguard: derived pcrlock path: %s\n", pcrPath)
	return pcrPath
}

// getBootedUKIPath reads the LoaderImageIdentifier EFI variable to get the booted UKI path
// Returns the path relative to /boot (e.g., /boot/EFI/Gentoo/kernel.efi)
func getBootedUKIPath() string {
	// LoaderImageIdentifier is set by systemd-stub/systemd-boot
	// GUID: 4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
	efiVarPath := "/sys/firmware/efi/efivars/LoaderImageIdentifier-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

	data, err := os.ReadFile(efiVarPath)
	if err != nil {
		console.DebugPrint("vanguard: LoaderImageIdentifier not available: %v\n", err)
		return ""
	}

	// EFI variable format: 4-byte attributes + UTF-16LE string
	if len(data) < 6 {
		return ""
	}

	// Skip 4-byte attribute header, decode UTF-16LE
	utf16Data := data[4:]
	path := decodeUTF16LE(utf16Data)

	// Convert backslashes to forward slashes and prepend /boot
	path = strings.ReplaceAll(path, "\\", "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = "/boot" + path

	console.DebugPrint("vanguard: booted UKI: %s\n", path)
	return path
}

// decodeUTF16LE decodes a UTF-16LE byte slice to a string
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Convert bytes to uint16 slice
	var runes []rune
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(data[i]) | rune(data[i+1])<<8
		if r == 0 {
			break // Null terminator
		}
		runes = append(runes, r)
	}

	return string(runes)
}

// getBootFromCmdline parses kernel cmdline for boot= parameter
func getBootFromCmdline() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		if strings.HasPrefix(param, "boot=") {
			return strings.TrimPrefix(param, "boot=")
		}
	}
	return ""
}

// findBootPartition scans block devices to find a partition containing pcrlock.json
func findBootPartition() string {
	// Get expected pcrlock path from booted UKI
	pcrLockPath := getPCRLockPath()
	if pcrLockPath == "" {
		console.DebugPrint("vanguard: cannot determine pcrlock path, skipping boot scan\n")
		return ""
	}

	// Read /sys/block to find all block devices
	sysBlocks, err := os.ReadDir("/sys/block")
	if err != nil {
		return ""
	}

	var candidates []string
	for _, block := range sysBlocks {
		name := block.Name()
		// Skip ram, loop, and dm devices
		if strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "dm-") {
			continue
		}

		// Look for partitions (e.g., sda1, sda2, nvme0n1p1)
		partitions, _ := filepath.Glob(filepath.Join("/sys/block", name, name+"*"))
		for _, part := range partitions {
			partName := filepath.Base(part)
			partDev := filepath.Join("/dev", partName)
			if _, err := os.Stat(partDev); err == nil {
				candidates = append(candidates, partDev)
			}
		}
	}

	// Try each candidate - mount as vfat and check for pcrlock.json at derived path
	for _, dev := range candidates {
		if err := unix.Mount(dev, "/boot", "vfat", unix.MS_RDONLY, ""); err == nil {
			// Check if pcrlock.json exists at the derived path
			if _, err := os.Stat(pcrLockPath); err == nil {
				console.DebugPrint("vanguard: found pcrlock on %s\n", dev)
				unix.Unmount("/boot", 0)
				return dev
			}
			unix.Unmount("/boot", 0)
		}
	}

	return ""
}
