package main

// CLI defines the root command structure with subcommands
type CLI struct {
	Generate      GenerateCmd      `cmd:"" help:"Generate initramfs image"`
	UpdatePolicy  UpdatePolicyCmd  `cmd:"" name:"update-tpm-policy" help:"Update TPM2 pcrlock policy"`
	VerifyPCRLock VerifyPCRLockCmd `cmd:"" name:"verify-pcrlock-setup" help:"Verify TPM2 pcrlock setup (PCRs, NV Index, LUKS)"`
}

// GenerateCmd generates a new initramfs image
type GenerateCmd struct {
	Output      string   `short:"o" required:"" help:"Output path for initramfs image"`
	Firmware    []string `short:"f" sep:"," help:"Firmware files to include (relative to /lib/firmware/)"`
	Modules     []string `short:"m" sep:"," help:"Kernel modules to include"`
	Compression string   `short:"c" default:"zstd" enum:"gzip,zstd,none" help:"Compression algorithm"`
	Debug       bool     `short:"d" help:"Enable debug output in init binary"`
	Strict      bool     `short:"s" help:"Strict mode: enforce token-only unlock (no passphrase fallback)"`
	Config      string   `type:"path" help:"Path to TOML config file"`
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
}
