# Vanguard Configuration

This document covers all configuration options for Vanguard.

## Command Line Interface

### generate

Generate an initramfs image.

```bash
vanguard generate [options]
```

#### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--output` | `-o` | string | *required* | Output path for the initramfs image |
| `--firmware` | `-f` | string | | Comma-separated list of firmware files to include |
| `--modules` | `-m` | string | | Comma-separated list of kernel modules to include |
| `--compression` | `-c` | string | `zstd` | Compression algorithm: `zstd`, `gzip`, or `none` |
| `--debug` | `-d` | bool | `false` | Enable verbose debug output in init |
| `--strict` | `-s` | bool | `false` | Strict mode: enforce token-only unlock (no passphrase fallback) |
| `--config` | | string | | Path to TOML configuration file |

#### Examples

```bash
# Basic generation
vanguard generate -o /boot/initramfs-linux.img

# With firmware
vanguard generate -o /boot/initramfs-linux.img \
  -f "amd/amd_sev.fw,amdgpu/vangogh_sos.bin"

# With modules
vanguard generate -o /boot/initramfs-linux.img \
  -m "nvme,xhci_pci,i915"

# Debug mode
vanguard generate -o /boot/initramfs-linux.img -d

# Using config file
vanguard generate --config /etc/vanguard.toml
```

### update-tpm-policy

Update TPM2 PCRLock policy for secure boot. Requires root privileges.

```bash
vanguard update-tpm-policy [options]
```

#### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--uki-path` | `-u` | string | *required* | Path to the Unified Kernel Image (UKI) |
| `--policy-output` | `-p` | string | `<uki-path>.pcrlock.json` | Output path for policy JSON |
| `--luks-device` | `-l` | string | | LUKS device for token verification (enables GPT binding) |
| `--no-gpt` | | bool | `false` | Disable GPT partition table binding (PCR 5) |
| `--no-verify` | | bool | `false` | Skip policy verification step |
| `--verbose` | `-v` | bool | `false` | Show verbose output from pcrlock tools |
| `--cleanup` | `-c` | bool | `false` | Remove old unused pcrlock NV indices from TPM |

#### What It Does

1. Configures PCR masks (disables PCR 15 which causes timing issues with Vanguard)
2. Locks Secure Boot state (PCR 7)
3. Locks GPT partition table (PCR 5) - **auto-enabled when `--luks-device` is specified**
4. Locks UKI measurement (PCR 4) using `lock-pe` with `lock-uki` fallback
5. Generates policy with recovery PIN prompt
6. Verifies the generated policy

#### Examples

```bash
# Basic policy update
sudo vanguard update-tpm-policy -u /boot/EFI/Linux/kernel.efi

# With custom output path
sudo vanguard update-tpm-policy -u /boot/EFI/Linux/kernel.efi \
  -p /boot/pcrlock.json

# With LUKS device for token verification
sudo vanguard update-tpm-policy -u /boot/EFI/Linux/kernel.efi \
  -l /dev/sda2

# Skip verification
sudo vanguard update-tpm-policy -u /boot/EFI/Linux/kernel.efi --no-verify
```

## Configuration File

Vanguard can be configured using a TOML file. By default, it looks for `/etc/vanguard.toml`.

### File Format

```toml
# Output path for generated initramfs
output = "/boot/initramfs-linux.img"

# Compression algorithm: "zstd", "gzip", or "none"
compression = "zstd"

# Enable debug output in init binary
debug = false

# Strict mode: enforce token-only unlock (no passphrase fallback)
strict_mode = false

# Firmware files to include (relative to /lib/firmware/)
firmware = [
    "amd/amd_sev.fw",
    "amdgpu/vangogh_sos.bin",
    "i915/skl_dmc_ver1_27.bin",
]

# Kernel modules to include
modules = [
    "nvme",
    "xhci_pci",
    "i915",
    "amdgpu",
]
```

### Options Reference

#### output
- **Type:** string
- **Default:** `/boot/initramfs-linux.img`
- **Description:** Path where the generated initramfs will be written.

#### compression
- **Type:** string
- **Default:** `zstd`
- **Values:** `zstd`, `gzip`, `none`
- **Description:** Compression algorithm for the initramfs.

| Algorithm | Speed | Size | Notes |
|-----------|-------|------|-------|
| `zstd` | Fast | Smallest | Recommended, best balance |
| `gzip` | Medium | Medium | Wide compatibility |
| `none` | Fastest | Largest | For debugging |

#### debug
- **Type:** bool
- **Default:** `false`
- **Description:** When enabled, the init binary outputs verbose messages during boot. Useful for debugging boot issues.

#### strict_mode
- **Type:** bool
- **Default:** `false`
- **Description:** When enabled with a TPM2 token present, disables passphrase fallback. Boot halts if TPM2 unlock fails.

#### firmware
- **Type:** array of strings
- **Default:** `[]`
- **Description:** List of firmware files to include, relative to `/lib/firmware/`. Firmware is added to an early uncompressed CPIO so it's available to built-in kernel drivers.

#### modules
- **Type:** array of strings
- **Default:** `[]`
- **Description:** List of kernel modules to include. Modules are loaded during early boot.

## Included Binaries

The generator automatically includes these binaries and their library dependencies:

| Binary | Purpose | Required |
|--------|---------|----------|
| `cryptsetup` | LUKS device management | Yes |
| `lvm` | LVM volume management | Yes |
| `dmsetup` | Device mapper control (udev rules require `/sbin/dmsetup`) | Yes |
| `systemd-udevd` | Device event daemon | Yes |
| `udevadm` | udev administration | Yes |
| `tpm2_pcrread` | TPM PCR debugging (shows values on unlock failure) | Optional |
| `tpm2_pcrextend` | TPM PCR extension (LUKS header measurement) | Optional |
| `loadkeys` | Keyboard layout loading | Optional |
| `setfont` | Console font loading | Optional |
| `fsck` | Generic filesystem check wrapper | Optional |
| `fsck.ext4` / `e2fsck` | ext4 filesystem check | Optional |

The generator searches multiple paths for each binary (e.g., `/usr/bin/`, `/sbin/`, `/bin/`) and uses the first one found.

## Included Files

### Always Included

| File | Purpose |
|------|---------|
| `/etc/fstab` | Root device detection (fallback if `root=` not in cmdline) |
| `/etc/vconsole.conf` | Keyboard/font settings (only if file exists) |

### udev Rules

Minimal set of udev rules for device-mapper:

- `09-dm-persist.rules` - Custom rule for switch_root survival
- `10-dm.rules` - Core device-mapper rules
- `11-dm-lvm.rules` - LVM symlink creation
- `13-dm-disk.rules` - DM disk symlinks
- `95-dm-notify.rules` - udev completion signaling

## Environment Variables

Vanguard does not currently use environment variables for configuration. All settings are passed via command line or config file.

## Precedence

When the same option is specified in multiple places, the following precedence applies (highest to lowest):

1. Command line flags
2. Configuration file
3. Default values

Example:
```bash
# Config file has: compression = "gzip"
# Command line wins:
vanguard generate -c zstd --config /etc/vanguard.toml -o /boot/initramfs.img
# Result: zstd compression is used
```

## Validation

The generator validates:

- Output path is writable
- Firmware files exist in `/lib/firmware/`
- Required binaries are available
- Compression algorithm is valid

Warnings are printed for:
- Missing optional binaries (tpm2_pcrread, etc.)
- Missing firmware files
- Missing kernel modules
