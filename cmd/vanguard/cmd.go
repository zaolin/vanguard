package main

// CLI defines the root command structure with subcommands
type CLI struct {
	Generate     GenerateCmd     `cmd:"" help:"Generate initramfs image"`
	UpdatePolicy UpdatePolicyCmd `cmd:"" name:"update-tpm-policy" help:"Update TPM2 pcrlock policy"`
}

// GenerateCmd generates a new initramfs image
type GenerateCmd struct {
	Output      string   `short:"o" required:"" help:"Output path for initramfs image"`
	Firmware    []string `short:"f" sep:"," help:"Firmware files to include (relative to /lib/firmware/)"`
	Modules     []string `short:"m" sep:"," help:"Kernel modules to include"`
	Compression string   `short:"c" default:"zstd" enum:"gzip,zstd,none" help:"Compression algorithm"`
	Debug       bool     `short:"d" help:"Enable debug output in init binary"`
	Config      string   `type:"path" help:"Path to TOML config file"`
}

// UpdatePolicyCmd updates TPM2 pcrlock policy
type UpdatePolicyCmd struct {
	UKIPath      string `short:"u" required:"" help:"Path to UKI file (e.g., /boot/EFI/Gentoo/kernel.efi)"`
	PolicyOutput string `short:"p" default:"/etc/boot-bundle/pcrlock.json" help:"Output path for policy JSON"`
	BundleDir    string `default:"/etc/boot-bundle" help:"Directory for policy files"`
	LUKSDevice   string `short:"l" help:"LUKS device to measure (e.g., /dev/nvme0n1p2)"`
	NoVerify     bool   `help:"Skip policy verification"`
}
