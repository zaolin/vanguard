package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode/utf16"
)

// sbctlInfo contains sbctl-derived Secure Boot verification data.
// sbctl is an optional tool — if not installed, all fields are empty/zero
// and the threat model silently skips sbctl-based checks.
type sbctlInfo struct {
	Installed       bool            `json:"installed"`
	EnrolledFiles   []sbctlFile     `json:"enrolledFiles,omitempty"`
	VerifyResults   []sbctlVerified `json:"verifyResults,omitempty"`
	BootedUKISigned *bool           `json:"bootedUkiSigned,omitempty"` // nil = unknown (not root or sbctl missing)
	BootedUKIPath   string          `json:"bootedUkiPath,omitempty"`
}

type sbctlFile struct {
	File       string `json:"file"`
	OutputFile string `json:"outputFile"`
}

// sbctlVerified matches the JSON output of `sbctl verify --json`.
// IsSigned: 1 = signed, 0 = unsigned, -1 = missing.
type sbctlVerified struct {
	FileName string `json:"file_name"`
	IsSigned int8   `json:"is_signed"`
}

// sbctlEnrolledKey represents a single certificate from sbctl list-enrolled-keys.
type sbctlEnrolledKey struct {
	CommonName string `json:"commonName"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
}

// sbctlEnrolledKeys holds the parsed key info from sbctl list-enrolled-keys.
type sbctlEnrolledKeys struct {
	PK  []sbctlEnrolledKey `json:"pk"`
	KEK []sbctlEnrolledKey `json:"kek"`
	DB  []sbctlEnrolledKey `json:"db"`
}

// collectSbctlStatus gathers sbctl data if sbctl is installed.
// Returns Installed=false if sbctl is not on PATH (silent skip).
func collectSbctlStatus() *sbctlInfo {
	info := &sbctlInfo{}

	if _, err := exec.LookPath("sbctl"); err != nil {
		return info // not installed — silent skip
	}
	info.Installed = true

	// Read enrolled files from files.json (world-readable)
	info.EnrolledFiles = readSbctlFilesDB()

	// Detect which UKI was booted (reads EFI BootCurrent variable, no root needed)
	info.BootedUKIPath = detectBootedUKI()

	// Run sbctl verify --json (requires root for key access)
	if os.Geteuid() == 0 {
		info.VerifyResults = runSbctlVerify()
	}

	// Check if the booted UKI is signed
	if info.BootedUKIPath != "" && len(info.VerifyResults) > 0 {
		for _, v := range info.VerifyResults {
			if v.FileName == info.BootedUKIPath {
				signed := v.IsSigned == 1
				info.BootedUKISigned = &signed
				break
			}
		}
	}

	return info
}

// collectSbctlEnrolledKeys reads PK/KEK/db cert metadata via
// `sbctl list-enrolled-keys --json` (no root needed — reads EFI vars).
// Returns nil if sbctl is not installed or the command fails.
func collectSbctlEnrolledKeys() *sbctlEnrolledKeys {
	if _, err := exec.LookPath("sbctl"); err != nil {
		return nil
	}

	output, err := exec.Command("sbctl", "list-enrolled-keys", "--json").Output()
	if err != nil {
		return nil
	}

	// sbctl list-enrolled-keys --json returns a map with "PK", "KEK", "DB" keys.
	// Each value is an array of Go x509.Certificate JSON structs.
	// We only extract CommonName, NotBefore, NotAfter for display.
	var raw map[string][]map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil
	}

	result := &sbctlEnrolledKeys{}
	result.PK = parseEnrolledKeyList(raw["PK"])
	result.KEK = parseEnrolledKeyList(raw["KEK"])
	result.DB = parseEnrolledKeyList(raw["DB"])
	return result
}

func parseEnrolledKeyList(certs []map[string]interface{}) []sbctlEnrolledKey {
	var keys []sbctlEnrolledKey
	for _, c := range certs {
		key := sbctlEnrolledKey{
			NotBefore: getString(c, "NotBefore"),
			NotAfter:  getString(c, "NotAfter"),
		}
		if subject, ok := c["Subject"].(map[string]interface{}); ok {
			key.CommonName = getString(subject, "CommonName")
		}
		keys = append(keys, key)
	}
	return keys
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// readSbctlFilesDB reads /var/lib/sbctl/files.json (world-readable).
func readSbctlFilesDB() []sbctlFile {
	data, err := os.ReadFile("/var/lib/sbctl/files.json")
	if err != nil {
		return nil
	}

	var raw map[string]struct {
		File       string `json:"file"`
		OutputFile string `json:"output_file"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var files []sbctlFile
	for _, f := range raw {
		files = append(files, sbctlFile{
			File:       f.File,
			OutputFile: f.OutputFile,
		})
	}
	return files
}

// runSbctlVerify runs `sbctl verify --json` as root and returns the results.
func runSbctlVerify() []sbctlVerified {
	output, err := exec.Command("sbctl", "verify", "--json").Output()
	if err != nil {
		return nil
	}

	var results []sbctlVerified
	if err := json.Unmarshal(output, &results); err != nil {
		return nil
	}
	return results
}

// detectBootedUKI reads the EFI BootCurrent and Boot#### variables to determine
// which EFI binary was booted. Returns the Linux filesystem path (e.g.,
// "/boot/EFI/Gentoo/kernel.efi") or empty string if unknown.
func detectBootedUKI() string {
	bootNum, err := readBootCurrent()
	if err != nil {
		return ""
	}

	efiPath, err := readBootEntryPath(bootNum)
	if err != nil {
		return ""
	}

	// Convert EFI path (\EFI\Gentoo\kernel.efi) to Linux path
	// by prepending the ESP mount point.
	espMount := detectESPMountPoint()
	if espMount == "" {
		return ""
	}

	// EFI paths use backslash separators; convert to forward slashes
	linuxRel := strings.ReplaceAll(efiPath, "\\", "/")
	// Remove leading slash if present
	linuxRel = strings.TrimPrefix(linuxRel, "/")

	return espMount + "/" + linuxRel
}

// readBootCurrent reads the BootCurrent EFI variable and returns the boot entry number.
func readBootCurrent() (uint16, error) {
	data, err := os.ReadFile("/sys/firmware/efi/efivars/BootCurrent-" + efiVarGUID)
	if err != nil {
		return 0, err
	}
	// 4-byte attributes + 2-byte uint16 (little-endian)
	if len(data) < 6 {
		return 0, fmt.Errorf("BootCurrent too short: %d bytes", len(data))
	}
	return binary.LittleEndian.Uint16(data[4:6]), nil
}

// readBootEntryPath reads the Boot#### EFI variable and extracts the file path
// from the EFI_LOAD_OPTION structure.
func readBootEntryPath(bootNum uint16) (string, error) {
	bootVarName := fmt.Sprintf("Boot%04X-%s", bootNum, efiVarGUID)
	data, err := os.ReadFile("/sys/firmware/efi/efivars/" + bootVarName)
	if err != nil {
		return "", err
	}

	// Skip 4-byte attributes
	varData := data[4:]
	if len(varData) < 6 {
		return "", fmt.Errorf("Boot%04X too short", bootNum)
	}

	// EFI_LOAD_OPTION:
	//   uint32 Attributes
	//   uint16 FilePathListLength
	//   char16 Description[] (null-terminated UTF-16LE)
	//   EFI_DEVICE_PATH_PROTOCOL FilePathList[]
	//   uint8 OptionalData[]

	// Skip Attributes (4) and FilePathListLength (2)
	offset := 6

	// Skip Description (null-terminated UTF-16LE)
	for offset+1 < len(varData) {
		ch := binary.LittleEndian.Uint16(varData[offset : offset+2])
		offset += 2
		if ch == 0 {
			break
		}
	}

	// Parse device path entries to find Media File Path (Type 0x04, SubType 0x04)
	for offset+4 <= len(varData) {
		dpType := varData[offset]
		dpSubtype := varData[offset+1]
		dpLen := binary.LittleEndian.Uint16(varData[offset+2 : offset+4])

		if dpLen < 4 || offset+int(dpLen) > len(varData) {
			break
		}

		if dpType == 0x04 && dpSubtype == 0x04 {
			// Media File Path: 4-byte header + UTF-16LE name
			nameData := varData[offset+4 : offset+int(dpLen)]
			// Remove trailing null terminator (2 bytes)
			if len(nameData) >= 2 && nameData[len(nameData)-2] == 0 && nameData[len(nameData)-1] == 0 {
				nameData = nameData[:len(nameData)-2]
			}
			// Decode UTF-16LE
			u16 := make([]uint16, 0, len(nameData)/2)
			for i := 0; i+1 < len(nameData); i += 2 {
				u16 = append(u16, binary.LittleEndian.Uint16(nameData[i:i+2]))
			}
			return string(utf16.Decode(u16)), nil
		}

		if dpType == 0x7F && dpSubtype == 0xFF {
			break // End of Hardware Device Path
		}

		offset += int(dpLen)
	}

	return "", fmt.Errorf("no Media File Path found in Boot%04X", bootNum)
}

// detectESPMountPoint finds where the EFI System Partition is mounted.
// Checks /proc/mounts for common ESP mount points.
func detectESPMountPoint() string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}

	// Common ESP mount points, in priority order
	candidates := []string{"/boot/efi", "/efi", "/boot"}

	for _, candidate := range candidates {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == candidate {
				// Verify it's vfat (typical for ESP)
				if len(fields) >= 3 && (fields[2] == "vfat" || fields[2] == "exfat") {
					return candidate
				}
				// Even if not vfat, accept /boot as it's commonly the ESP on UKI systems
				if candidate == "/boot" {
					return candidate
				}
			}
		}
	}

	// Fallback: check if any of these exist as mount points even without vfat
	for _, candidate := range candidates {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == candidate {
				return candidate
			}
		}
	}

	return "/boot" // last resort fallback
}
