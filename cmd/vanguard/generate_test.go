package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/zaolin/vanguard/internal/cpio"
)

func TestExtractGroupsFromRule(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "50-udev-default.rules")
	content := `# Udev rules
SUBSYSTEM=="tty", GROUP="tty"
SUBSYSTEM=="drm", GROUP="video", OWNER="root"
KERNEL=="null", GROUP="kmem"
`
	if err := os.WriteFile(rulePath, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	groups, owners := extractGroupsFromRule(rulePath)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d: %v", len(groups), groups)
	}
	if groups[0] != "tty" || groups[1] != "video" || groups[2] != "kmem" {
		t.Errorf("groups: got %v, want [tty video kmem]", groups)
	}
	if len(owners) != 1 {
		t.Fatalf("expected 1 owner, got %d: %v", len(owners), owners)
	}
	if owners[0] != "root" {
		t.Errorf("owner: got %s, want root", owners[0])
	}
}

func TestExtractGroupsFromRuleMissing(t *testing.T) {
	groups, owners := extractGroupsFromRule("/nonexistent/rule")
	if groups != nil || owners != nil {
		t.Error("expected nil for missing file")
	}
}

func TestExtractGroupsFromRuleEmpty(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "empty.rules")
	if err := os.WriteFile(rulePath, []byte("# only comments\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	groups, owners := extractGroupsFromRule(rulePath)
	if len(groups) != 0 || len(owners) != 0 {
		t.Error("expected empty for comments-only file")
	}
}

func TestCopyGroupEntries(t *testing.T) {
	if _, err := os.Stat("/etc/group"); err != nil {
		t.Skip("/etc/group not available")
	}
	var buf bytes.Buffer
	arch := cpio.NewArchive(&buf)
	count := copyGroupEntries(arch, []string{"root", "tty"})
	if count == 0 {
		t.Log("no matching groups found")
	}
	arch.Close()
}

func TestCopyPasswdEntries(t *testing.T) {
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Skip("/etc/passwd not available")
	}
	var buf bytes.Buffer
	arch := cpio.NewArchive(&buf)
	count := copyPasswdEntries(arch, []string{"root"})
	if count == 0 {
		t.Log("no matching passwd entries found")
	}
	arch.Close()
}
