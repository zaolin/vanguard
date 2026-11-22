package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectTSME_FindsNestedStatusFile is the regression test for the
// broken TSME lookup.
//
// The old implementation used filepath.Glob("/sys/devices/**/tsme_status").
// Go's filepath.Glob has no recursive "**" wildcard — it matches a single
// path segment — so the glob never matched the real sysfs path
// (/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2/tsme_status, three
// levels deep). AMD TSME memory encryption was therefore reported as
// "not-available" even when it was active.
func TestDetectTSME_FindsNestedStatusFile(t *testing.T) {
	root := t.TempDir()

	// Mirror the real sysfs depth: devices/<bus>/<device>/<function>/tsme_status
	nested := filepath.Join(root, "pci0000:00", "0000:00:08.1", "0000:c1:00.2")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "tsme_status"), []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	active, count := detectTSMEIn(root)
	if !active {
		t.Errorf("detectTSMEIn(%s) = false, want true — nested tsme_status not found", root)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

// TestDetectTSME_CountsAllStatusFiles pins that every status file is
// counted, not just the first match.
func TestDetectTSME_CountsAllStatusFiles(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{
		filepath.Join("pci0000:00", "0000:00:08.1", "0000:c1:00.2"),
		filepath.Join("pci0000:00", "0000:00:16.0", "0000:c2:00.2"),
	} {
		dir := filepath.Join(root, p)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tsme_status"), []byte("1\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	active, count := detectTSMEIn(root)
	if !active {
		t.Error("active = false, want true")
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

// TestDetectTSME_InactiveWhenZero pins that a status file reporting 0 means
// TSME is present but not active.
func TestDetectTSME_InactiveWhenZero(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pci0000:00", "0000:00:08.1", "0000:c1:00.2")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tsme_status"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	active, count := detectTSMEIn(root)
	if active {
		t.Error("active = true, want false (tsme_status reports 0)")
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (the file exists)", count)
	}
}

// TestDetectTSME_NoStatusFiles pins the empty case.
func TestDetectTSME_NoStatusFiles(t *testing.T) {
	root := t.TempDir()
	active, count := detectTSMEIn(root)
	if active || count != 0 {
		t.Errorf("got active=%v count=%d, want false/0", active, count)
	}
}
