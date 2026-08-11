package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Output != "/boot/initramfs-linux.img" {
		t.Errorf("Output: got %s, want /boot/initramfs-linux.img", cfg.Output)
	}
	if cfg.Compression != "zstd" {
		t.Errorf("Compression: got %s, want zstd", cfg.Compression)
	}
	if len(cfg.Firmware) != 0 {
		t.Errorf("Firmware: expected empty, got %v", cfg.Firmware)
	}
	if len(cfg.Modules) != 0 {
		t.Errorf("Modules: expected empty, got %v", cfg.Modules)
	}
	if cfg.Debug {
		t.Error("Debug: expected false")
	}
}

func TestLoadEmpty(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path: %v", err)
	}
	if cfg.Output != "/boot/initramfs-linux.img" {
		t.Errorf("Output: got %s, want default", cfg.Output)
	}
}

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanguard.toml")
	content := `output = "/custom/initramfs.img"
compression = "gzip"
debug = true
firmware = ["amd/sev.fw", "amdgpu/vangogh.bin"]
modules = ["nvme", "xhci_pci"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output != "/custom/initramfs.img" {
		t.Errorf("Output: got %s, want /custom/initramfs.img", cfg.Output)
	}
	if cfg.Compression != "gzip" {
		t.Errorf("Compression: got %s, want gzip", cfg.Compression)
	}
	if !cfg.Debug {
		t.Error("Debug: expected true")
	}
	if len(cfg.Firmware) != 2 {
		t.Fatalf("Firmware: expected 2 entries, got %d", len(cfg.Firmware))
	}
	if cfg.Firmware[0] != "amd/sev.fw" {
		t.Errorf("Firmware[0]: got %s, want amd/sev.fw", cfg.Firmware[0])
	}
	if len(cfg.Modules) != 2 {
		t.Fatalf("Modules: expected 2 entries, got %d", len(cfg.Modules))
	}
	if cfg.Modules[0] != "nvme" {
		t.Errorf("Modules[0]: got %s, want nvme", cfg.Modules[0])
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/path/to/config.toml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanguard.toml")
	content := `compression = "none"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Compression != "none" {
		t.Errorf("Compression: got %s, want none", cfg.Compression)
	}
	if cfg.Output != "/boot/initramfs-linux.img" {
		t.Errorf("Output: should remain default, got %s", cfg.Output)
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanguard.toml")
	content := `this is not valid toml {{{`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}