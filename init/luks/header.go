package luks

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/zaolin/vanguard/init/buildtags"
)

// LUKS2Info contains validated header facts for a LUKS2 device.
// Only what the token finder needs — the full volume geometry lives in
// internal/luks (LUKS2Volume), which is used for actual unlocking.
type LUKS2Info struct {
	BackingDevice string
	Version       int
	HeaderSize    uint64
	JSONSize      uint64
}

// GetLUKS2Info validates the LUKS2 header on devicePath and returns the
// validated header facts.
func GetLUKS2Info(devicePath string) (*LUKS2Info, error) {
	hdrLen, err := readValidatedHeaderLen(devicePath)
	if err != nil {
		return nil, err
	}

	return &LUKS2Info{
		BackingDevice: devicePath,
		Version:       2,
		HeaderSize:    hdrLen,
		JSONSize:      hdrLen - 0x1000,
	}, nil
}

// maxLUKS2HeaderLen bounds the validated LUKS2 header length (16 MB, well
// above cryptsetup's 4 MB maximum) to prevent pre-auth allocation blowups
// from corrupt or hostile headers.
const maxLUKS2HeaderLen = 16 * 1024 * 1024

// readValidatedHeaderLen reads the LUKS2 binary header from devicePath and
// returns the validated header length (hdr_len field). It verifies the LUKS
// magic, the LUKS2 version, and that hdr_len is within [0x1000,
// maxLUKS2HeaderLen]. All header readers must go through this function — a
// hostile hdr_len (e.g. 0xFFFFFFFFFFFFFFFF from a corrupt or evil-maid-
// crafted header) must never reach a make([]byte, size) allocation.
func readValidatedHeaderLen(devicePath string) (uint64, error) {
	binHeader, err := readDeviceRange(devicePath, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to read LUKS2 binary header: %w", err)
	}

	if len(binHeader) < 8 || string(binHeader[0:4]) != "LUKS" {
		return 0, fmt.Errorf("not a LUKS device: %s", devicePath)
	}

	version := binary.BigEndian.Uint16(binHeader[6:8])
	if version != 2 {
		return 0, fmt.Errorf("only LUKS2 is supported (found version %d)", version)
	}

	hdrLen := binary.BigEndian.Uint64(binHeader[8:16])
	if hdrLen < 0x1000 || hdrLen > maxLUKS2HeaderLen {
		return 0, fmt.Errorf("invalid LUKS2 header length: %d", hdrLen)
	}
	return hdrLen, nil
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

// readDeviceRange reads exactly size bytes from a device at the given
// offset. It loops via io.ReadFull — single Read calls can return short on
// block devices (driver limits, signals), which would silently truncate
// header hashes and break PCR 11 binding determinism.
func readDeviceRange(devicePath string, offset uint64, size uint64) ([]byte, error) {
	f, err := os.Open(devicePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make([]byte, size)
	if _, err := f.ReadAt(data, int64(offset)); err != nil && err != io.EOF {
		return nil, err
	}

	return data, nil
}

// HashLUKS2Header reads the full LUKS2 header (binary header + JSON area)
// from the device and returns its SHA256 hash as a 32-byte digest.
// The header size is determined from the hdr_len field at offset 8.
//
// This hash is extended into PCR 11 to bind the pcrlock policy to the
// on-disk LUKS header state. Any change to the header (e.g., adding or
// removing a keyslot) will change the hash and cause a PCR mismatch.
func HashLUKS2Header(devicePath string) ([]byte, error) {
	// Validate magic, version, and hdr_len bounds via the shared reader.
	hdrLen, err := readValidatedHeaderLen(devicePath)
	if err != nil {
		return nil, err
	}

	// Read the full header (binary header + JSON area)
	fullHeader, err := readDeviceRange(devicePath, 0, hdrLen)
	if err != nil {
		return nil, fmt.Errorf("failed to read full LUKS2 header: %w", err)
	}

	// Hash with SHA256
	hash := sha256.Sum256(fullHeader)
	buildtags.Debug("luks: LUKS2 header hash (%s, %d bytes): %s\n",
		devicePath, hdrLen, hex.EncodeToString(hash[:]))
	return hash[:], nil
}
