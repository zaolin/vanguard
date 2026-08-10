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

### update

Update TPM2 PCRLock policy for secure boot. Requires root privileges.

```bash
vanguard update [options]
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

#### 5-Phase Execution

1. **PCR Masks** — Masks noisy/unstable PCRs, unmaskes stable PCRs 2, 3
2. **Lock PCRs** — Locks Secure Boot (PCR 7), GPT (PCR 5, with `-l`), UKI (PCR 4 with PE fallback)
3. **Make Policy** — Runs `systemd-pcrlock make-policy` with recovery PIN
4. **Verify** — Validates that PCR 7 is present in the generated policy
5. **Integrity Check** — Verifies NV index sync and PCR values against the TPM

#### Examples

```bash
# Basic policy update
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi

# With custom output path
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -p /boot/custom.json

# With LUKS device (enables GPT binding on PCR 5)
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2

# Skip verification
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi --no-verify

# Clean up old NV indices
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2 -c
```

### verify

Verify TPM2 pcrlock setup (PCRs, NV Index, LUKS token).

```bash
vanguard verify [options]
```

#### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--policy-path` | `-p` | string | *required* | Path to pcrlock.json policy file |
| `--luks-device` | `-l` | string | | LUKS device to verify token on |

#### Checks Performed

1. **NV Index Synchronization** — TPM auth policy + size vs policy file
2. **PCR Validation** — Current PCR values against policy expectations
3. **LUKS Token** — Token NV index match + pcrlock enforcement (with `-l`)

#### Examples

```bash
# Verify NV index and PCRs
sudo vanguard verify -p /boot/EFI/Gentoo/kernel.pcrlock.json

# Include LUKS token validation
sudo vanguard verify -p /boot/EFI/Gentoo/kernel.pcrlock.json -l /dev/nvme0n1p2
```

### status

Show system protection status.

```bash
vanguard status [options]
```

#### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--json` | | bool | `false` | Machine-readable JSON output |

#### What It Shows

A threat-model-first view organized by attack vectors:

- **Protection tier** — PHYSICAL / HIGH / WARNING / CRITICAL / LOW with visual bar
- **Threat vectors** — 10 attack vectors with per-mitigation status:
  - Evil Maid (initrd/UKI replacement) — Secure Boot, PCRLock PCR 7, sbctl, Platform Fused, PSB
  - Boot Chain Tampering — PCRLock PCR binding, NV index, PCR0 reconstruction
  - TPM Key Extraction — TPM 2.0, fTPM detection, bus encryption, DA lockout
  - DMA Attack — IOMMU, pre-boot DMA protection, Thunderbolt
  - Kernel Runtime Attack — lockdown, module sigs, CET, SMAP, kernel tainted
  - Cold Boot Attack — memory encryption (informational, doesn't affect tier)
  - Brute-Force / Key Theft — TPM2 token, PIN, PCRLock binding, TOTP fallback
  - Physical Debug Attack — debug interface locked, fused part (via fwupd/HSTI)
  - Firmware Tampering — SPI write/replay protection, anti-rollback (via fwupd/HSTI)
  - SMM Attack — SMM locked (via fwupd)
- **Platform integration** — fwupd HSI attributes, sbctl signature verification, AMD HSTI sysfs

#### Examples

```bash
# Show protection status (expanded view with all mitigations)
vanguard status

# Machine-readable output
vanguard status --json
```

### recovery

Manage TOTP-based boot recovery. Without flags, prints recovery instructions.

```bash
vanguard recovery [options]
```

#### Options

| Option | Description |
|--------|-------------|
| `--enable` | Generate TOTP seed, write to TPM NVRAM, display QR code for authenticator app enrollment |
| `--show` | Show current TOTP seed and QR code (for re-enrollment). Also displays pending re-provisioned seed if `--auto-reseed` ran after firmware update |
| `--disable` | Remove TOTP recovery seed from TPM NVRAM |
| `--clean` | Forcefully remove old/legacy recovery NV indexes (for migration from older vanguard versions) |
| `--auto-reseed` | Automatically re-provision recovery seed if unreadable (PCR 7 changed after firmware update). Non-interactive — for systemd service use |
| `-l, --luks-device` | LUKS device path (used in recovery instructions) |
| `--nv-index` | TPM NV index for recovery data (default: 0x01C30001) |

#### Examples

```bash
# Enable TOTP recovery (interactive — displays QR code, prompts for verification)
sudo vanguard recovery --enable

# Show current seed and QR code
sudo vanguard recovery --show

# Disable recovery
sudo vanguard recovery --disable

# Re-provision after firmware update (non-interactive — for systemd services)
sudo vanguard recovery --auto-reseed

# Clean legacy NV indexes (migration from older vanguard)
sudo vanguard recovery --clean
```

### enroll

Enroll TPM2 token on a LUKS device (runs `vanguard update` + `systemd-cryptenroll`):

```bash
vanguard enroll -u <uki> -l <luks-device> [options]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--uki-path` | `-u` | Path to the UKI file (required) |
| `--luks-device` | `-l` | LUKS device path (required) |
| `--with-pin` | | Enable PIN protection for the TPM2 token |
| `--verbose` | `-v` | Show verbose output |

### inspect

Inspect contents of a generated initramfs:

```bash
vanguard inspect -p <path> [options]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--path` | `-p` | Path to the initramfs image (required) |
| `--verbose` | `-v` | Show file sizes |

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

| Algorithm | Speed | Size | Notes |
|-----------|-------|------|-------|
| `zstd` | Fast | Smallest | Recommended, best balance |
| `gzip` | Medium | Medium | Wide compatibility |
| `none` | Fastest | Largest | For debugging |

#### debug
- **Type:** bool
- **Default:** `false`
- **Description:** When enabled, the init binary outputs verbose messages during boot. Useful for debugging boot issues. Equivalent to `-d` flag.

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
|--------|---------|:--------:|
| `lvm` | LVM volume management | Yes |
| `dmsetup` | Device mapper control (udev rules require `/sbin/dmsetup`) | Yes |
| `systemd-udevd` | Device event daemon | Yes |
| `udevadm` | udev administration | Yes |
| `loadkeys` | Keyboard layout loading | Optional |
| `setfont` | Console font loading | Optional |
| `fsck` | Generic filesystem check wrapper | Optional |
| `fsck.ext4` / `e2fsck` | ext4 filesystem check | Optional |

**LUKS and TPM2 operations use native Go** — no `cryptsetup` or `tpm2-tools` binaries are needed at runtime. The init binary handles LUKS header parsing, key derivation, dm-crypt setup, and TPM2 sealed key unseal internally.

## Included Files

### Always Included

| File | Purpose |
|------|---------|
| `/etc/fstab` | Root device detection (fallback if `root=` not in cmdline) |

### Conditional

| File | Condition |
|------|-----------|
| `/etc/vconsole.conf` | Included if file exists on host |
| Keymap data files | Included if `/usr/share/kbd/keymaps` or `/lib/kbd/keymaps` exists |

### udev Rules

Minimal set of udev rules for device-mapper and graphics:

| Rule | Purpose |
|------|---------|
| `09-dm-persist.rules` | Custom: db_persist for DM devices across switch_root |
| `10-dm.rules` | Core device-mapper rules |
| `11-dm-lvm.rules` | LVM symlink creation (`/dev/<vg>/<lv>`) |
| `13-dm-disk.rules` | DM disk symlinks |
| `50-udev-default.rules` | Default device permissions |
| `60-drm.rules` | DRM device rules (graphics/Wayland) |
| `70-uaccess.rules` | User access control |
| `71-seat.rules` | Multi-seat device handling |
| `73-seat-late.rules` | Late seat assignment |
| `95-dm-notify.rules` | udev completion signaling (dmsetup udevcomplete) |

## Precedence

When the same option is specified in multiple places (highest to lowest):

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
- Required binaries are available on the host
- Compression algorithm is valid

Warnings are printed for missing optional binaries or firmware files.
