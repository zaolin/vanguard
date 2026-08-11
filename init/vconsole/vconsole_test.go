package vconsole

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseVconsoleConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vconsole.conf")
	content := `KEYMAP=de-latin1
FONT=eurlatgr
KEYMAP_TOGGLE=us
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := parseVconsoleConf(path)
	if err != nil {
		t.Fatalf("parseVconsoleConf: %v", err)
	}
	if cfg.Keymap != "de-latin1" {
		t.Errorf("Keymap: got %s, want de-latin1", cfg.Keymap)
	}
	if cfg.Font != "eurlatgr" {
		t.Errorf("Font: got %s, want eurlatgr", cfg.Font)
	}
	if cfg.KeymapToggle != "us" {
		t.Errorf("KeymapToggle: got %s, want us", cfg.KeymapToggle)
	}
}

func TestParseVconsoleConfMissing(t *testing.T) {
	_, err := parseVconsoleConf("/nonexistent/vconsole.conf")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseVconsoleConfEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vconsole.conf")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := parseVconsoleConf(path)
	if err != nil {
		t.Fatalf("parseVconsoleConf: %v", err)
	}
	if cfg.Keymap != "" || cfg.Font != "" {
		t.Error("expected empty config for empty file")
	}
}

// parseCmdlineOverrides and keymapFilesExist take no args (read /proc/cmdline, scan dirs)
func TestParseCmdlineOverrides(t *testing.T) {
	_ = parseCmdlineOverrides()
}

func TestKeymapFilesExist(t *testing.T) {
	_ = keymapFilesExist()
}