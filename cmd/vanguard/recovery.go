package main

import "os/exec"

// RecoveryCmd manages TOTP recovery for a Vanguard-protected system.
// Without flags, prints recovery instructions. With --enable, generates
// a TOTP seed and stores it in TPM NVRAM. With --disable, removes it.
type RecoveryCmd struct {
	LUKSDevice string `short:"l" help:"LUKS device path (e.g., /dev/nvme0n1p2)"`
	Enable     bool   `help:"Enable TOTP recovery (generate seed, write to TPM NVRAM, display QR code)"`
	Disable    bool   `help:"Disable TOTP recovery (remove seed from TPM NVRAM)"`
	Show       bool   `help:"Show current TOTP seed and QR code (for re-enrollment)"`
	Check      bool   `help:"Verify that TOTP recovery is properly configured and the seed is readable"`
	Clean      bool   `help:"Forcefully remove old/legacy recovery NV indexes (for migration from older vanguard versions)"`
	AutoReseed bool   `help:"Automatically re-provision recovery seed if unreadable (for firmware update convergence — non-interactive)"`
	NVIndex    uint32 `help:"TPM NV index for recovery data (default: 0x01C30001)"`
}

// execLookPathImpl wraps exec.LookPath.
func execLookPathImpl(name string) (string, error) {
	return exec.LookPath(name)
}
