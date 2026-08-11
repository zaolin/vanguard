package mount

import "testing"

func TestHasOption(t *testing.T) {
	tests := []struct {
		opts string
		opt  string
		want bool
	}{
		{"defaults", "defaults", true},
		{"rw,noatime", "noatime", true},
		{"rw,noatime", "rw", true},
		{"rw,noatime", "ro", false},
		{"defaults", "noatime", false},
		{"", "defaults", false},
	}
	for _, tt := range tests {
		got := hasOption(tt.opts, tt.opt)
		if got != tt.want {
			t.Errorf("hasOption(%q, %q) = %v, want %v", tt.opts, tt.opt, got, tt.want)
		}
	}
}

func TestIsPseudoFS(t *testing.T) {
	pseudo := []string{"proc", "sysfs", "devtmpfs", "tmpfs", "devpts", "debugfs", "tracefs", "cgroup", "cgroup2", "fusectl", "securityfs", "configfs", "pstore", "mqueue", "bpf"}
	for _, fs := range pseudo {
		if !isPseudoFS(fs) {
			t.Errorf("isPseudoFS(%q) = false, want true", fs)
		}
	}
	real := []string{"ext4", "xfs", "btrfs", "vfat", "ntfs", "f2fs", "zfs"}
	for _, fs := range real {
		if isPseudoFS(fs) {
			t.Errorf("isPseudoFS(%q) = true, want false", fs)
		}
	}
}

func TestNormalizeLVMPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/dev/vg0/root", "/dev/mapper/vg0-root"},
		{"/dev/mapper/vg0-root", "/dev/mapper/vg0-root"},
		{"/dev/sda2", "/dev/sda2"},
		{"/dev/nvme0n1p2", "/dev/nvme0n1p2"},
	}
	for _, tt := range tests {
		got := normalizeLVMPath(tt.input)
		if got != tt.want {
			t.Errorf("normalizeLVMPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	b := []byte{0x45, 0x00, 0x46, 0x00, 0x49, 0x00}
	got := decodeUTF16LE(b)
	if got != "EFI" {
		t.Errorf("decodeUTF16LE: got %q, want EFI", got)
	}
}

// getRootFromCmdline and getBootFromCmdline read /proc/cmdline directly
func TestGetRootFromCmdline(t *testing.T) {
	_, _ = getRootFromCmdline()
}

func TestGetBootFromCmdline(t *testing.T) {
	_ = getBootFromCmdline()
}