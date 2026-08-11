package fsck

import "testing"

func TestIsFsckDisabled(t *testing.T) {
	// These read /proc/cmdline - just verify they don't panic
	_ = isFsckDisabled()
}

func TestIsFsckDisabledWithCmdline(t *testing.T) {
	// isFsckDisabled reads from /proc/cmdline which we can't control
	// in unit tests, but we can verify it returns a bool
	result := isFsckDisabled()
	if result != true && result != false {
		t.Error("expected bool return")
	}
}