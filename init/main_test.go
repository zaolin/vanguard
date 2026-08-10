package main

import (
	"strings"
	"testing"
)

// cmdlineParam is a utility for extracting key=value parameters from
// kernel cmdline strings. It is currently unused in production (the
// vanguard.strict=0 override was removed), but kept for future use
// (e.g., parsing init= or other boot parameters).
func cmdlineParam(cmdline, key string) string {
	for _, field := range strings.Fields(cmdline) {
		if strings.HasPrefix(field, key+"=") {
			return strings.TrimPrefix(field, key+"=")
		}
	}
	return ""
}

func TestCmdlineParam(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		key     string
		want    string
	}{
		{
			name:    "simple value",
			cmdline: "root=/dev/sda1 vanguard.strict=0 quiet",
			key:     "vanguard.strict",
			want:    "0",
		},
		{
			name:    "param not found",
			cmdline: "root=/dev/sda1 quiet",
			key:     "vanguard.strict",
			want:    "",
		},
		{
			name:    "empty cmdline",
			cmdline: "",
			key:     "vanguard.strict",
			want:    "",
		},
		{
			name:    "param at end",
			cmdline: "root=/dev/sda1 quiet vanguard.strict=1",
			key:     "vanguard.strict",
			want:    "1",
		},
		{
			name:    "param at start",
			cmdline: "vanguard.strict=0 root=/dev/sda1",
			key:     "vanguard.strict",
			want:    "0",
		},
		{
			name:    "multiple params",
			cmdline: "root=/dev/sda1 vanguard.strict=0 vanguard.debug=1 quiet",
			key:     "vanguard.debug",
			want:    "1",
		},
		{
			name:    "boolean flag (no value)",
			cmdline: "root=/dev/sda1 debug quiet",
			key:     "debug",
			want:    "",
		},
		{
			name:    "similar key not matched",
			cmdline: "vanguard.strictmode=1 root=/dev/sda1",
			key:     "vanguard.strict",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cmdlineParam(tt.cmdline, tt.key)
			if got != tt.want {
				t.Errorf("cmdlineParam(%q, %q) = %q, want %q",
					tt.cmdline, tt.key, got, tt.want)
			}
		})
	}
}
