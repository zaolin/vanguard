package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

// Config holds the vanguard configuration
type Config struct {
	Output      string   `toml:"output"`
	Compression string   `toml:"compression"`
	Firmware    []string `toml:"firmware"`
	Modules     []string `toml:"modules"`
	Debug       bool     `toml:"debug"`
	UKIPath     string   `toml:"uki_path"`
	LUKSDevice  string   `toml:"luks_device"`
	InitBinary  string   `toml:"-"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Output:      "/boot/initramfs-linux.img",
		Compression: "zstd",
		Firmware:    []string{},
		Modules:     []string{},
	}
}

// Load loads configuration from a TOML file
// If path is empty, returns default config
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
