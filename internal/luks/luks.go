package luks

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

// Device represents a LUKS encrypted device
type Device struct {
	Path string
	UUID string
	Name string // from crypttab, if available
}

// Detect finds all LUKS devices on the system using blkid
// and validates them with cryptsetup isLuks
func Detect() ([]Device, error) {
	out, err := exec.Command("blkid", "-t", "TYPE=crypto_LUKS", "-o", "device").Output()
	if err != nil {
		// No LUKS devices found is not an error
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return nil, nil
		}
		return nil, err
	}

	var devices []Device
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			// Validate with cryptsetup isLuks
			if IsLuks(line) {
				dev := Device{Path: line}
				// Get UUID
				if uuid, err := getUUID(line); err == nil {
					dev.UUID = uuid
				}
				devices = append(devices, dev)
			}
		}
	}

	// Enrich with crypttab info
	enrichFromCrypttab(devices)

	return devices, nil
}

// IsLuks validates that a device is a LUKS container using cryptsetup
func IsLuks(devicePath string) bool {
	err := exec.Command("cryptsetup", "isLuks", devicePath).Run()
	return err == nil
}

// getUUID retrieves the UUID of a LUKS device
func getUUID(devicePath string) (string, error) {
	out, err := exec.Command("cryptsetup", "luksUUID", devicePath).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// enrichFromCrypttab adds name information from /etc/crypttab
func enrichFromCrypttab(devices []Device) {
	crypttab, err := parseCrypttab("/etc/crypttab")
	if err != nil {
		return
	}

	for i := range devices {
		for _, entry := range crypttab {
			if entry.Device == devices[i].Path ||
				entry.Device == "UUID="+devices[i].UUID ||
				entry.Device == "/dev/disk/by-uuid/"+devices[i].UUID {
				devices[i].Name = entry.Name
				break
			}
		}
	}
}

// crypttabEntry represents a single crypttab entry
type crypttabEntry struct {
	Name    string
	Device  string
	KeyFile string
	Options string
}

// parseCrypttab parses /etc/crypttab
func parseCrypttab(path string) ([]crypttabEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []crypttabEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			entry := crypttabEntry{
				Name:   fields[0],
				Device: fields[1],
			}
			if len(fields) >= 3 {
				entry.KeyFile = fields[2]
			}
			if len(fields) >= 4 {
				entry.Options = fields[3]
			}
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}
