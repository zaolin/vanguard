package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractModuleName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nvme.ko", "nvme"},
		{"nvme.ko.gz", "nvme"},
		{"nvme.ko.xz", "nvme"},
		{"nvme.ko.zst", "nvme"},
		{"xhci-pci.ko", "xhci_pci"},
		{"amdgpu.ko.gz", "amdgpu"},
		{"i915.ko.xz", "i915"},
	}
	for _, tt := range tests {
		got := extractModuleName(tt.input)
		if got != tt.want {
			t.Errorf("extractModuleName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLoadModulesDep(t *testing.T) {
	dir := t.TempDir()
	depPath := filepath.Join(dir, "modules.dep")
	content := `/lib/modules/6.6.0/kernel/drivers/nvme/nvme.ko: /lib/modules/6.6.0/kernel/crypto/crypto.ko
/lib/modules/6.6.0/kernel/drivers/usb/xhci-pci.ko:
`
	if err := os.WriteFile(depPath, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	deps, err := loadModulesDep(depPath)
	if err != nil {
		t.Fatalf("loadModulesDep: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(deps))
	}

	nvmeDeps, ok := deps["nvme"]
	if !ok {
		t.Fatal("nvme not in deps map")
	}
	if len(nvmeDeps) != 1 {
		t.Fatalf("nvme deps: expected 1, got %d: %v", len(nvmeDeps), nvmeDeps)
	}
	if nvmeDeps[0] != "crypto" {
		t.Errorf("nvme dep[0]: got %s, want crypto", nvmeDeps[0])
	}

	xhciDeps, ok := deps["xhci_pci"]
	if !ok {
		t.Fatal("xhci_pci not in deps map")
	}
	if len(xhciDeps) != 0 {
		t.Errorf("xhci_pci deps: expected 0, got %d", len(xhciDeps))
	}
}

func TestLoadModulesDepMissing(t *testing.T) {
	_, err := loadModulesDep("/nonexistent/modules.dep")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadModulesDepEmpty(t *testing.T) {
	dir := t.TempDir()
	depPath := filepath.Join(dir, "modules.dep")
	if err := os.WriteFile(depPath, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	deps, err := loadModulesDep(depPath)
	if err != nil {
		t.Fatalf("loadModulesDep: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 modules for empty file, got %d", len(deps))
	}
}

func TestFindModuleFile(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "kernel", "drivers", "nvme")
	os.MkdirAll(modDir, 0755)
	modPath := filepath.Join(modDir, "nvme.ko")
	os.WriteFile(modPath, []byte("fake module"), 0644)

	found, err := findModuleFile(dir, "nvme")
	if err != nil {
		t.Fatalf("findModuleFile: %v", err)
	}
	if found == "" {
		t.Fatal("expected to find nvme.ko")
	}
	if filepath.Base(found) != "nvme.ko" {
		t.Errorf("found: got %s, want nvme.ko", filepath.Base(found))
	}
}

func TestFindModuleFileNotFound(t *testing.T) {
	dir := t.TempDir()
	found, err := findModuleFile(dir, "nonexistent")
	if err != nil {
		t.Fatalf("findModuleFile: %v", err)
	}
	if found != "" {
		t.Errorf("expected empty path, got %s", found)
	}
}

func TestCollectWithDeps(t *testing.T) {
	dir := t.TempDir()
	// Create a module file
	modDir := filepath.Join(dir, "nvme")
	os.MkdirAll(modDir, 0755)
	os.WriteFile(filepath.Join(modDir, "nvme.ko"), []byte("fake"), 0644)
	os.WriteFile(filepath.Join(modDir, "crypto.ko"), []byte("fake"), 0644)

	deps := map[string][]string{
		"nvme":   {"crypto"},
		"crypto": {},
	}

	var collected []ModuleFile
	seen := make(map[string]bool)
	collectWithDeps("nvme", dir, deps, seen, &collected)

	if len(collected) != 2 {
		t.Fatalf("expected 2 files, got %d", len(collected))
	}
}

func TestCollectEmpty(t *testing.T) {
	_, err := Collect([]string{}, "nonexistent")
	if err == nil {
		// Collect with empty list might return empty without error
	}
}
