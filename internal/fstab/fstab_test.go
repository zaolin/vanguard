package fstab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	content := `/dev/nvme0n1p2 / ext4 defaults 0 1
/dev/nvme0n1p1 /boot vfat defaults 0 2
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Device != "/dev/nvme0n1p2" {
		t.Errorf("entry[0] Device: got %s", entries[0].Device)
	}
	if entries[0].Mountpoint != "/" {
		t.Errorf("entry[0] Mountpoint: got %s", entries[0].Mountpoint)
	}
	if entries[0].FSType != "ext4" {
		t.Errorf("entry[0] FSType: got %s", entries[0].FSType)
	}
	if entries[1].Mountpoint != "/boot" {
		t.Errorf("entry[1] Mountpoint: got %s", entries[1].Mountpoint)
	}
}

func TestParseComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	content := `# This is a comment

# Another comment
/dev/sda1 / ext4 defaults 0 1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (comments/empty lines skipped), got %d", len(entries))
	}
}

func TestParseMissingFile(t *testing.T) {
	_, err := Parse("/nonexistent/fstab")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty file, got %d", len(entries))
	}
}

func TestFindRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	content := `/dev/nvme0n1p1 /boot vfat defaults 0 2
/dev/nvme0n1p2 / ext4 defaults 0 1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	root, err := FindRoot(path)
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	if root != "/dev/nvme0n1p2" {
		t.Errorf("root: got %s, want /dev/nvme0n1p2", root)
	}
}

func TestFindRootNoRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	content := `/dev/sda1 /home ext4 defaults 0 2
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	root, err := FindRoot(path)
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	if root != "" {
		t.Errorf("root: got %s, want empty string", root)
	}
}

func TestFindRootDefaultPath(t *testing.T) {
	// FindRoot with no args should read /etc/fstab - skip if it doesn't exist
	root, err := FindRoot()
	if err != nil {
		// /etc/fstab might not exist in test environment - that's ok
		return
	}
	_ = root
}