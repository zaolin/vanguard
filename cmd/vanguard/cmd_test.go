package main

import (
	"testing"
)

func TestPcrName(t *testing.T) {
	tests := []struct {
		pcr  int
		want string
	}{
		{2, "external-code"},
		{3, "external-config"},
		{4, "boot-loader-code"},
		{5, "GPT-partition"},
		{7, "secure-boot-policy"},
		{0, "unknown"},
		{99, "unknown"},
	}

	for _, tt := range tests {
		got := pcrName(tt.pcr)
		if got != tt.want {
			t.Errorf("pcrName(%d) = %q, want %q", tt.pcr, got, tt.want)
		}
	}
}

func TestBox(t *testing.T) {
	// box should produce a non-empty string with the title and content
	result := box("Test Title", []string{"line 1", "line 2"})
	if result == "" {
		t.Error("box returned empty string")
	}

	// Without a title
	result = box("", []string{"only line"})
	if result == "" {
		t.Error("box with empty title returned empty string")
	}
}

func TestGetParentDisk(t *testing.T) {
	// Non-existent device should return empty string
	result := getParentDisk("/dev/nonexistent-device")
	if result != "" {
		t.Errorf("expected empty string for nonexistent device, got %q", result)
	}
}

func TestSanitizeInitramfsPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "absolute path",
			path: "/lib/firmware/test.bin",
			want: "lib/firmware/test.bin",
		},
		{
			name: "relative path (no leading slash)",
			path: "lib/firmware/test.bin",
			want: "lib/firmware/test.bin",
		},
		{
			name: "path traversal - single dot",
			path: "/lib/./firmware/test.bin",
			want: "lib/firmware/test.bin",
		},
		{
			name:    "path traversal - double dot at root",
			path:    "/../etc/shadow",
			want:    "",
			wantErr: true,
		},
		{
			name:    "path traversal - nested",
			path:    "/lib/../../../etc/passwd",
			want:    "",
			wantErr: true,
		},
		{
			name: "path traversal - mid path (cleaned to non-traversal)",
			path: "/lib/firmware/../../etc/shadow",
			want: "etc/shadow",
		},
		{
			name: "path traversal - mid path with .. component after clean",
			path: "/lib/../etc/shadow",
			want: "etc/shadow", // filepath.Clean resolves .. → valid in-initramfs path
		},
		{
			name:    "path traversal - deep nested .. that escapes root",
			path:    "/a/b/c/../../../../d",
			want:    "",
			wantErr: true,
		},
		{
			name: "deep valid path",
			path: "/usr/lib/firmware/amd/gpu/vangogh_sos.bin",
			want: "usr/lib/firmware/amd/gpu/vangogh_sos.bin",
		},
		{
			name: "single segment",
			path: "/test.bin",
			want: "test.bin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeInitramfsPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("sanitizeInitramfsPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestTruncateHash(t *testing.T) {
	tests := []struct {
		hash string
		want string
	}{
		{"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "abcdef0123456789..."},
		{"short", "short"},
		{"", ""},
		{"exactly16chars", "exactly16chars"},
		{"morethansixteenchars", "morethansixteenc..."},
	}

	for _, tt := range tests {
		got := truncateHash(tt.hash)
		if got != tt.want {
			t.Errorf("truncateHash(%q) = %q, want %q", tt.hash, got, tt.want)
		}
	}
}
