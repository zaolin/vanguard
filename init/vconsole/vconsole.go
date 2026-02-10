package vconsole

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Config holds vconsole configuration from /etc/vconsole.conf
type Config struct {
	Keymap       string
	KeymapToggle string
	Font         string
	FontMap      string
	FontUnimap   string
}

// Debug function placeholder - will be set by the main init package
var Debug func(format string, args ...any) = func(format string, args ...any) {}

// Binary paths for loadkeys and setfont
var loadkeysPaths = []string{
	"/usr/bin/loadkeys",
	"/bin/loadkeys",
}

var setfontPaths = []string{
	"/usr/bin/setfont",
	"/bin/setfont",
}

// Configure loads and applies vconsole settings from /etc/vconsole.conf
// It also checks for kernel cmdline overrides (vconsole.keymap=, vconsole.font=)
func Configure() error {
	// Parse config file
	cfg, err := parseVconsoleConf("/etc/vconsole.conf")
	if err != nil {
		Debug("vconsole: failed to parse config: %v\n", err)
		// Not an error if file doesn't exist
		cfg = &Config{}
	}

	// Check for kernel cmdline overrides
	overrides := parseCmdlineOverrides()
	if overrides.Keymap != "" {
		cfg.Keymap = overrides.Keymap
	}
	if overrides.Font != "" {
		cfg.Font = overrides.Font
	}

	// Apply keymap if specified (skip if keymap files not in initramfs)
	if cfg.Keymap != "" {
		if !keymapFilesExist() {
			Debug("vconsole: keymap %s requested but keymap files not in initramfs, skipping\n", cfg.Keymap)
		} else if err := loadKeymap(cfg.Keymap); err != nil {
			Debug("vconsole: failed to load keymap %s: %v\n", cfg.Keymap, err)
		} else {
			Debug("vconsole: loaded keymap %s\n", cfg.Keymap)
		}
	}

	// Apply toggle keymap if specified
	if cfg.KeymapToggle != "" {
		if !keymapFilesExist() {
			Debug("vconsole: keymap toggle %s requested but keymap files not in initramfs, skipping\n", cfg.KeymapToggle)
		} else if err := loadKeymap(cfg.KeymapToggle); err != nil {
			Debug("vconsole: failed to load toggle keymap %s: %v\n", cfg.KeymapToggle, err)
		}
	}

	// Apply font if specified
	if cfg.Font != "" {
		fontArgs := []string{cfg.Font}
		if cfg.FontMap != "" {
			fontArgs = append(fontArgs, "-m", cfg.FontMap)
		}
		if cfg.FontUnimap != "" {
			fontArgs = append(fontArgs, "-u", cfg.FontUnimap)
		}
		if err := loadFont(fontArgs...); err != nil {
			Debug("vconsole: failed to load font %s: %v\n", cfg.Font, err)
		} else {
			Debug("vconsole: loaded font %s\n", cfg.Font)
		}
	}

	return nil
}

// parseVconsoleConf parses /etc/vconsole.conf
// Format: shell-like variable assignments (KEY=value)
func parseVconsoleConf(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, "\"'")

		switch key {
		case "KEYMAP":
			cfg.Keymap = value
		case "KEYMAP_TOGGLE":
			cfg.KeymapToggle = value
		case "FONT":
			cfg.Font = value
		case "FONT_MAP":
			cfg.FontMap = value
		case "FONT_UNIMAP":
			cfg.FontUnimap = value
		}
	}

	return cfg, scanner.Err()
}

// parseCmdlineOverrides checks kernel cmdline for vconsole.* parameters
func parseCmdlineOverrides() *Config {
	cfg := &Config{}

	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return cfg
	}

	cmdline := string(data)
	for _, param := range strings.Fields(cmdline) {
		if strings.HasPrefix(param, "vconsole.keymap=") {
			cfg.Keymap = strings.TrimPrefix(param, "vconsole.keymap=")
		} else if strings.HasPrefix(param, "vconsole.font=") {
			cfg.Font = strings.TrimPrefix(param, "vconsole.font=")
		} else if strings.HasPrefix(param, "vconsole.font_map=") {
			cfg.FontMap = strings.TrimPrefix(param, "vconsole.font_map=")
		} else if strings.HasPrefix(param, "vconsole.font_unimap=") {
			cfg.FontUnimap = strings.TrimPrefix(param, "vconsole.font_unimap=")
		} else if strings.HasPrefix(param, "vconsole.keymap_toggle=") {
			cfg.KeymapToggle = strings.TrimPrefix(param, "vconsole.keymap_toggle=")
		}
	}

	return cfg
}

// keymapDirs are the directories where keymap files are stored
var keymapDirs = []string{
	"/usr/share/kbd/keymaps",
	"/lib/kbd/keymaps",
	"/usr/lib/kbd/keymaps",
}

// keymapFilesExist checks if keymap data files are available in the initramfs
func keymapFilesExist() bool {
	for _, dir := range keymapDirs {
		if _, err := os.Stat(dir); err == nil {
			return true
		}
	}
	return false
}

// loadKeymap loads a keyboard layout using loadkeys
func loadKeymap(keymap string) error {
	binary := findBinary(loadkeysPaths)
	if binary == "" {
		return fmt.Errorf("loadkeys binary not found")
	}

	// Skip if keymap files aren't included in initramfs
	if !keymapFilesExist() {
		return fmt.Errorf("keymap files not found in initramfs")
	}

	cmd := exec.Command(binary, keymap)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// loadFont loads a console font using setfont
func loadFont(args ...string) error {
	binary := findBinary(setfontPaths)
	if binary == "" {
		return fmt.Errorf("setfont binary not found")
	}

	cmd := exec.Command(binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// findBinary searches for a binary in the given paths
func findBinary(paths []string) string {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
