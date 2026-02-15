package luks

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/zaolin/vanguard/init/buildtags"
)

// LUKS2Info contains parsed information from LUKS2 header.
type LUKS2Info struct {
	BackingDevice     string
	StorageEncryption string
	StorageSectorSize uint32
	StorageOffset     uint64
	StorageSize       uint64
	Version           int
	HeaderSize        uint64
	JSONSize          uint64
}

// GetLUKS2Info reads the LUKS2 header directly from the device and returns LUKS2Info.
func GetLUKS2Info(devicePath string) (*LUKS2Info, error) {
	vol := &LUKS2Info{
		BackingDevice:     devicePath,
		StorageSectorSize: 512,
		StorageOffset:     0x1000,
	}

	headerSize := uint64(0x1000)
	data, err := readDeviceRange(devicePath, 0, headerSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	// Check for LUKS magic "LUKS\xba\xbe" at offset 0
	if len(data) < 8 || string(data[0:4]) != "LUKS" {
		return nil, fmt.Errorf("not a LUKS device")
	}

	// Check LUKS version
	version := binary.BigEndian.Uint16(data[6:8])
	vol.Version = int(version)
	vol.HeaderSize = headerSize

	if version != 2 {
		return nil, fmt.Errorf("only LUKS2 is supported (found version %d)", version)
	}

	// Parse LUKS2 JSON header
	return parseLUKS2Header(devicePath, vol)
}

// parseLUKS2Header parses LUKS2 JSON header from the device.
func parseLUKS2Header(devicePath string, vol *LUKS2Info) (*LUKS2Info, error) {
	// Read binary header to get the header length
	headerData, err := readDeviceRange(devicePath, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to read LUKS2 binary header: %w", err)
	}

	// LUKS2 header format:
	//   Offset 8-15: hdr_len (big-endian uint64) - total header length including JSON area
	hdrLen := binary.BigEndian.Uint64(headerData[8:16])
	jsonSize := hdrLen - 0x1000

	vol.HeaderSize = hdrLen
	vol.JSONSize = jsonSize

	buildtags.Debug("luks: LUKS2 header length: %d, JSON size: %d\n", hdrLen, jsonSize)

	// Read the JSON area
	data, err := readDeviceRange(devicePath, 0x1000, jsonSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read LUKS2 JSON header: %w", err)
	}

	// Debug: print first 200 bytes of JSON area
	if len(data) > 0 {
		printLen := 200
		if len(data) < printLen {
			printLen = len(data)
		}
		buildtags.Debug("luks: JSON area first %d bytes: %s\n", printLen, string(data[:printLen]))
	}

	// Find the JSON boundary
	jsonEnd := findJSONEnd(data)
	if jsonEnd <= 0 {
		return nil, fmt.Errorf("failed to find JSON boundary in LUKS2 header")
	}

	buildtags.Debug("luks: JSON ends at byte %d\n", jsonEnd)

	// Parse JSON directly (no config.json wrapper)
	var config struct {
		Cipher     string `json:"cipher"`
		CipherMode string `json:"cipherMode"`
		Hash       string `json:"hash"`
		UUID       string `json:"uuid"`
		KeySlots   map[string]struct {
			Key struct {
				Size int `json:"size"`
			} `json:"key"`
		} `json:"keyslots"`
	}

	if err := json.Unmarshal(data[:jsonEnd], &config); err != nil {
		return nil, fmt.Errorf("failed to parse LUKS2 JSON: %w", err)
	}

	// Build cipher string
	if config.Cipher != "" && config.CipherMode != "" {
		vol.StorageEncryption = config.Cipher + "-" + config.CipherMode
	} else if config.CipherMode != "" {
		vol.StorageEncryption = config.CipherMode
	} else {
		vol.StorageEncryption = "aes-xts-plain64"
	}

	// Get device size
	devSize, err := getBlockDeviceSize(devicePath)
	if err == nil && devSize > 0 {
		vol.StorageSize = devSize - vol.StorageOffset
	}

	buildtags.Debug("luks: LUKS2 cipher: %s, offset: %d\n",
		vol.StorageEncryption, vol.StorageOffset)

	return vol, nil
}

// findJSONEnd finds the end of JSON data in a buffer (looks for closing brace).
func findJSONEnd(data []byte) int {
	// Find the last non-null character before trailing nulls/padding
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '}' {
			return i + 1
		}
		if data[i] != 0 {
			// Might not be JSON, try to find any closing brace
			break
		}
	}

	// Fallback: try to parse as JSON and see where it ends
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		return len(data)
	}

	// Last resort: find first '}' character
	for i, b := range data {
		if b == '}' {
			return i + 1
		}
	}

	return -1
}

// readDeviceRange reads from a device at the given offset and size.
func readDeviceRange(devicePath string, offset uint64, size uint64) ([]byte, error) {
	f, err := os.Open(devicePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, err = f.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	data := make([]byte, size)
	n, err := f.Read(data)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return data[:n], nil
}

// getBlockDeviceSize returns the size of a block device in bytes.
func getBlockDeviceSize(devicePath string) (uint64, error) {
	stat, err := os.Stat(devicePath)
	if err != nil {
		return 0, err
	}

	// For block devices, use stat.Size()
	// This works for regular files too (like disk images)
	return uint64(stat.Size()), nil
}
