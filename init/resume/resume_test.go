package resume

import "testing"

func TestNormalizeLVMPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/dev/vg0/swap", "/dev/mapper/vg0-swap"},
		{"/dev/mapper/vg0-swap", "/dev/mapper/vg0-swap"},
		{"/dev/sda3", "/dev/sda3"},
		{"/dev/nvme0n1p3", "/dev/nvme0n1p3"},
		{"UUID=1234", "UUID=1234"},
	}
	for _, tt := range tests {
		got := normalizeLVMPath(tt.input)
		if got != tt.want {
			t.Errorf("normalizeLVMPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEscapeMapperName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"vg0-root", "vg0--root"},
		{"vg-root-swap", "vg--root--swap"},
	}
	for _, tt := range tests {
		got := escapeMapperName(tt.input)
		if got != tt.want {
			t.Errorf("escapeMapperName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// parseResumeParam and parseResumeOffset read /proc/cmdline directly (no args)
// so they can't be unit tested with specific inputs - just verify they don't panic
func TestParseResumeParam(t *testing.T) {
	_ = parseResumeParam()
}

func TestParseResumeOffset(t *testing.T) {
	_ = parseResumeOffset()
}