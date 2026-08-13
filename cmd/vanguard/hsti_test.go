package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadHSTIInt(t *testing.T) {
	dir := t.TempDir()

	// Test value "1"
	path1 := filepath.Join(dir, "test1")
	if err := os.WriteFile(path1, []byte("1\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := readHSTIInt(path1); got != 1 {
		t.Errorf("readHSTIInt(1): got %d, want 1", got)
	}

	// Test value "0"
	path0 := filepath.Join(dir, "test0")
	if err := os.WriteFile(path0, []byte("0\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := readHSTIInt(path0); got != 0 {
		t.Errorf("readHSTIInt(0): got %d, want 0", got)
	}
}

func TestReadHSTIIntMissing(t *testing.T) {
	got := readHSTIInt("/nonexistent/path")
	if got != 0 {
		t.Errorf("readHSTIInt(missing): got %d, want 0", got)
	}
}

func TestReadHSTIIntGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage")
	if err := os.WriteFile(path, []byte("garbage"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := readHSTIInt(path)
	if got != 0 {
		t.Errorf("readHSTIInt(garbage): got %d, want 0", got)
	}
}

func TestCollectHSTIStatusNotAvailable(t *testing.T) {
	// On systems without CCP driver, HSTI should be unavailable
	info := collectHSTIStatus()
	if info == nil {
		t.Fatal("expected non-nil hstiInfo")
	}
	// On this system it might be available or not - just verify it doesn't panic
}
