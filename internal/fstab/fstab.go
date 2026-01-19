package fstab

import (
	"bufio"
	"os"
	"strings"
)

// Entry represents a single fstab entry
type Entry struct {
	Device     string
	Mountpoint string
	FSType     string
	Options    string
	Dump       int
	Pass       int
}

// Parse reads an fstab file and returns all entries
func Parse(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			entries = append(entries, Entry{
				Device:     fields[0],
				Mountpoint: fields[1],
				FSType:     fields[2],
				Options:    fields[3],
			})
		}
	}
	return entries, scanner.Err()
}

// FindRoot returns the device for the root mountpoint from /etc/fstab
func FindRoot() (string, error) {
	entries, err := Parse("/etc/fstab")
	if err != nil {
		return "", err
	}

	for _, e := range entries {
		if e.Mountpoint == "/" {
			return e.Device, nil
		}
	}
	return "", nil
}
