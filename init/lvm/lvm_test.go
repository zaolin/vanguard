package lvm

import "testing"

func TestFindVGLVSeparator(t *testing.T) {
	tests := []struct {
		input string
		sep   int
	}{
		{"vg0-root", 3},
		{"vg-root", 2},
		{"vg0--lv0-snap", 8}, // -- is escaped, separator is after
		{"noseparator", -1},
		{"", -1},
	}
	for _, tt := range tests {
		got := findVGLVSeparator(tt.input)
		if got != tt.sep {
			t.Errorf("findVGLVSeparator(%q) = %d, want %d", tt.input, got, tt.sep)
		}
	}
}

func TestUnescapeLVMName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"vg--root", "vg-root"},
		{"pre--post", "pre-post"},
		{"a--b--c", "a-b-c"},
	}
	for _, tt := range tests {
		got := unescapeLVMName(tt.input)
		if got != tt.want {
			t.Errorf("unescapeLVMName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsSpecialDevDir(t *testing.T) {
	specials := []string{"block", "bus", "char", "cpu", "disk", "dri", "mapper", "net", "pts", "shm", "snd"}
	for _, name := range specials {
		if !isSpecialDevDir(name) {
			t.Errorf("isSpecialDevDir(%q) = false, want true", name)
		}
	}
	nonSpecials := []string{"vg0", "sda1", "nvme0n1", "hda"}
	for _, name := range nonSpecials {
		if isSpecialDevDir(name) {
			t.Errorf("isSpecialDevDir(%q) = true, want false", name)
		}
	}
}
