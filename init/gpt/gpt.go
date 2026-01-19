package gpt

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GPT Partition Type GUIDs (Discoverable Partitions Specification)
// https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
const (
	// EFI System Partition
	ESPGUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

	// Root partition (x86-64)
	RootX86_64GUID = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"

	// Root partition (x86 32-bit)
	RootX86GUID = "44479540-f297-41b2-9af7-d131d5f0458a"

	// Root partition (ARM 64-bit)
	RootARM64GUID = "b921b045-1df0-41c3-af44-4c6f280d3fae"

	// Swap partition
	SwapGUID = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"

	// Home partition
	HomeGUID = "933ac7e1-2eb4-4f13-b844-0e14e2aef915"

	// Linux filesystem data (generic)
	LinuxFilesystemGUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"

	// Linux LVM
	LinuxLVMGUID = "e6d6d379-f507-44c2-a23c-238f2a3df928"

	// Linux LUKS
	LinuxLUKSGUID = "ca7d7ccb-63ed-4c53-861c-1742536059cc"
)

// GPT signature
var gptSignature = []byte("EFI PART")

// Debug function placeholder - will be set by the main init package
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// Partition represents a GPT partition entry
type Partition struct {
	TypeGUID   string // Partition type GUID
	UniqueGUID string // Unique partition GUID
	StartLBA   uint64 // First LBA of partition
	EndLBA     uint64 // Last LBA of partition
	Attributes uint64 // Partition attributes
	Name       string // Partition name (UTF-16LE, up to 36 chars)
	Number     int    // Partition number (1-based)
}

// GPTHeader represents the GPT header structure
type GPTHeader struct {
	Signature           [8]byte
	Revision            uint32
	HeaderSize          uint32
	HeaderCRC32         uint32
	Reserved            uint32
	CurrentLBA          uint64
	BackupLBA           uint64
	FirstUsableLBA      uint64
	LastUsableLBA       uint64
	DiskGUID            [16]byte
	PartitionEntryLBA   uint64
	NumPartitions       uint32
	PartitionEntrySize  uint32
	PartitionEntryCRC32 uint32
}

// ParseGPT reads and parses the GPT from a block device
func ParseGPT(device string) ([]Partition, error) {
	f, err := os.Open(device)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}
	defer f.Close()

	// Read GPT header at LBA 1 (512 bytes into disk)
	// Assuming 512-byte sectors (most common)
	sectorSize := int64(512)

	headerBuf := make([]byte, sectorSize)
	if _, err := f.ReadAt(headerBuf, sectorSize); err != nil {
		return nil, fmt.Errorf("failed to read GPT header: %w", err)
	}

	// Verify GPT signature
	if string(headerBuf[:8]) != string(gptSignature) {
		return nil, fmt.Errorf("invalid GPT signature")
	}

	// Parse header
	header := &GPTHeader{}
	header.Revision = binary.LittleEndian.Uint32(headerBuf[8:12])
	header.HeaderSize = binary.LittleEndian.Uint32(headerBuf[12:16])
	header.PartitionEntryLBA = binary.LittleEndian.Uint64(headerBuf[72:80])
	header.NumPartitions = binary.LittleEndian.Uint32(headerBuf[80:84])
	header.PartitionEntrySize = binary.LittleEndian.Uint32(headerBuf[84:88])

	Debug("gpt: found GPT with %d partition entries\n", header.NumPartitions)

	// Read partition entries
	entryOffset := int64(header.PartitionEntryLBA) * sectorSize
	entrySize := int64(header.PartitionEntrySize)
	if entrySize == 0 {
		entrySize = 128 // Default GPT entry size
	}

	var partitions []Partition
	entryBuf := make([]byte, entrySize)

	for i := uint32(0); i < header.NumPartitions; i++ {
		offset := entryOffset + int64(i)*entrySize
		if _, err := f.ReadAt(entryBuf, offset); err != nil {
			break // End of readable entries
		}

		// Parse partition entry
		typeGUID := parseGUID(entryBuf[0:16])
		uniqueGUID := parseGUID(entryBuf[16:32])

		// Skip empty entries (all zeros type GUID)
		if typeGUID == "00000000-0000-0000-0000-000000000000" {
			continue
		}

		startLBA := binary.LittleEndian.Uint64(entryBuf[32:40])
		endLBA := binary.LittleEndian.Uint64(entryBuf[40:48])
		attributes := binary.LittleEndian.Uint64(entryBuf[48:56])
		name := parseUTF16Name(entryBuf[56:128])

		partitions = append(partitions, Partition{
			TypeGUID:   typeGUID,
			UniqueGUID: uniqueGUID,
			StartLBA:   startLBA,
			EndLBA:     endLBA,
			Attributes: attributes,
			Name:       name,
			Number:     int(i) + 1,
		})
	}

	return partitions, nil
}

// parseGUID converts a 16-byte GUID to string format
func parseGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	// GUID is stored in mixed-endian format:
	// - First 3 components are little-endian
	// - Last 2 components are big-endian
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

// parseUTF16Name converts UTF-16LE partition name to string
func parseUTF16Name(b []byte) string {
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// FindPartitionByType finds the first partition with the given type GUID
func FindPartitionByType(partitions []Partition, typeGUID string) *Partition {
	typeGUID = strings.ToLower(typeGUID)
	for i := range partitions {
		if strings.ToLower(partitions[i].TypeGUID) == typeGUID {
			return &partitions[i]
		}
	}
	return nil
}

// FindAllPartitionsByType finds all partitions with the given type GUID
func FindAllPartitionsByType(partitions []Partition, typeGUID string) []Partition {
	typeGUID = strings.ToLower(typeGUID)
	var result []Partition
	for _, p := range partitions {
		if strings.ToLower(p.TypeGUID) == typeGUID {
			result = append(result, p)
		}
	}
	return result
}

// GetPartitionDevice returns the device path for a partition
// e.g., GetPartitionDevice("/dev/sda", 1) returns "/dev/sda1"
// e.g., GetPartitionDevice("/dev/nvme0n1", 1) returns "/dev/nvme0n1p1"
func GetPartitionDevice(diskDev string, partNum int) string {
	base := filepath.Base(diskDev)

	// NVMe devices use 'p' separator
	if strings.HasPrefix(base, "nvme") || strings.HasPrefix(base, "mmcblk") || strings.HasPrefix(base, "loop") {
		return fmt.Sprintf("%sp%d", diskDev, partNum)
	}

	// SCSI/SATA/IDE devices just append the number
	return fmt.Sprintf("%s%d", diskDev, partNum)
}

// DiscoverRootPartition scans all block devices to find a root partition
// using GPT type GUID autodiscovery
func DiscoverRootPartition() (string, error) {
	// Get list of block devices
	disks, err := listBlockDevices()
	if err != nil {
		return "", fmt.Errorf("failed to list block devices: %w", err)
	}

	Debug("gpt: scanning %d block devices for root partition\n", len(disks))

	for _, disk := range disks {
		partitions, err := ParseGPT(disk)
		if err != nil {
			Debug("gpt: %s: %v\n", disk, err)
			continue
		}

		// Look for root partition (x86-64)
		root := FindPartitionByType(partitions, RootX86_64GUID)
		if root != nil {
			device := GetPartitionDevice(disk, root.Number)
			Debug("gpt: found root partition: %s (partition %d on %s)\n", device, root.Number, disk)
			return device, nil
		}

		// Also check for generic Linux filesystem as fallback
		linux := FindPartitionByType(partitions, LinuxFilesystemGUID)
		if linux != nil {
			device := GetPartitionDevice(disk, linux.Number)
			Debug("gpt: found Linux filesystem partition: %s\n", device)
			// Don't return immediately - keep looking for proper root GUID
		}
	}

	return "", fmt.Errorf("no root partition found via GPT autodiscovery")
}

// DiscoverESP scans all block devices to find the EFI System Partition
func DiscoverESP() (string, error) {
	disks, err := listBlockDevices()
	if err != nil {
		return "", fmt.Errorf("failed to list block devices: %w", err)
	}

	for _, disk := range disks {
		partitions, err := ParseGPT(disk)
		if err != nil {
			continue
		}

		esp := FindPartitionByType(partitions, ESPGUID)
		if esp != nil {
			device := GetPartitionDevice(disk, esp.Number)
			Debug("gpt: found ESP: %s\n", device)
			return device, nil
		}
	}

	return "", fmt.Errorf("no ESP found via GPT autodiscovery")
}

// DiscoverSwapPartition scans all block devices to find a swap partition
func DiscoverSwapPartition() (string, error) {
	disks, err := listBlockDevices()
	if err != nil {
		return "", fmt.Errorf("failed to list block devices: %w", err)
	}

	for _, disk := range disks {
		partitions, err := ParseGPT(disk)
		if err != nil {
			continue
		}

		swap := FindPartitionByType(partitions, SwapGUID)
		if swap != nil {
			device := GetPartitionDevice(disk, swap.Number)
			Debug("gpt: found swap partition: %s\n", device)
			return device, nil
		}
	}

	return "", fmt.Errorf("no swap partition found via GPT autodiscovery")
}

// listBlockDevices returns a list of block device paths (disks, not partitions)
func listBlockDevices() ([]string, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	var devices []string
	for _, entry := range entries {
		name := entry.Name()

		// Skip ram, loop, and dm devices
		if strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "loop") ||
			strings.HasPrefix(name, "dm-") {
			continue
		}

		devPath := filepath.Join("/dev", name)
		if _, err := os.Stat(devPath); err == nil {
			devices = append(devices, devPath)
		}
	}

	return devices, nil
}

// IsGPTAutoEnabled checks if GPT autodiscovery is enabled via kernel cmdline
// Enabled by default, can be disabled with vanguard.gpt_auto=0
func IsGPTAutoEnabled() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return true // Default to enabled
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		if param == "vanguard.gpt_auto=0" || param == "vanguard.gpt_auto=no" {
			return false
		}
	}
	return true
}
