package main

import "github.com/alecthomas/kong"

// CLI defines the root command structure with subcommands
type CLI struct {
	Generate GenerateCmd      `cmd:"" help:"Generate initramfs image"`
	Update   UpdatePolicyCmd  `cmd:"" name:"update" help:"Update TPM2 pcrlock policy"`
	Verify   VerifyPCRLockCmd `cmd:"" name:"verify" help:"Verify TPM2 pcrlock setup (PCRs, NV Index, LUKS)"`
	Status   StatusCmd        `cmd:"" help:"Show system protection status"`
	Enroll   EnrollCmd        `cmd:"" help:"Enroll TPM2 token on LUKS device (runs update + systemd-cryptenroll)"`
	Recovery RecoveryCmd      `cmd:"" help:"Print recovery instructions"`
	Inspect  InspectCmd       `cmd:"" help:"Inspect contents of a generated initramfs"`

	Version kong.VersionFlag `short:"V" help:"Show version"`
}

// GenerateCmd generates a new initramfs image
type GenerateCmd struct {
	Output      string   `short:"o" required:"" help:"Output path for initramfs image"`
	Firmware    []string `short:"f" sep:"," help:"Firmware files to include (relative to /lib/firmware/)"`
	Modules     []string `short:"m" sep:"," help:"Kernel modules to include"`
	Compression string   `short:"c" default:"zstd" enum:"gzip,zstd,none" help:"Compression algorithm"`
	Debug       bool     `short:"d" help:"Enable debug output in init binary"`
	Verbose     bool     `short:"v" help:"Show verbose output during generation"`
	Config      string   `type:"path" help:"Path to TOML config file"`
	InitBinary  string   `help:"Path to custom init binary (for testing with -cover). If not set, uses the embedded binary."`
}

// UpdatePolicyCmd updates TPM2 pcrlock policy
type UpdatePolicyCmd struct {
	UKIPath      string `short:"u" required:"" help:"Path to UKI file (e.g., /boot/EFI/Gentoo/kernel.efi)"`
	PolicyOutput string `short:"p" help:"Output path for policy JSON (default: <uki-path>.pcrlock.json)"`
	LUKSDevice   string `short:"l" help:"LUKS device to measure (e.g., /dev/nvme0n1p2)"`
	NoGPT        bool   `help:"Disable GPT partition table binding (PCR 5). GPT binding is auto-enabled when --luks-device is specified."`
	NoVerify     bool   `help:"Skip policy verification"`
	Verbose      bool   `short:"v" help:"Show verbose output from pcrlock tools"`
	Cleanup      bool   `short:"c" help:"Remove old unused pcrlock NV indices from TPM"`
	DryRun       bool   `help:"Show what would be done without modifying TPM or writing policy"`
	JSON         bool   `help:"Output results as JSON (implies --dry-run for non-mutating commands)"`
}

// VerifyPCRLockCmd verifies TPM2 pcrlock setup
type VerifyPCRLockCmd struct {
	PolicyPath string `short:"p" required:"" help:"Path to pcrlock.json policy file"`
	LUKSDevice string `short:"l" help:"Path to LUKS device to verify (optional)"`
	JSON       bool   `help:"Output results as JSON"`
}

// StatusCmd shows system protection status
type StatusCmd struct {
	JSON bool `help:"Machine-readable JSON output"`
}
