<p align="center">
  <img src="assets/logo.png" alt="Vanguard Logo" width="200"/>
</p>

# Vanguard

A minimal, security-focused initramfs generator for Linux systems with full disk encryption. Written in Go, Vanguard creates lightweight boot images optimized for LUKS + LVM + TPM2 setups with PCRLock boot integrity enforcement.

## Security Guarantees

Vanguard binds disk encryption keys to the measured boot state of the platform. The disk can only be unlocked when the system boots from a known-good chain: firmware, bootloader, UKI, and Secure Boot configuration must all match the enrolled policy. An attacker who changes any of these - by replacing the UKI, flashing malicious firmware, disabling Secure Boot, or booting from a live USB - cannot unlock the disk.

### Attack Vectors and Mitigations

| Attack | What Vanguard does |
|--------|-------------------|
| Evil Maid (initrd/UKI replacement) | Secure Boot enforcement, PCRLock PCR 7 binding, sbctl signature verification, hardware validated boot (PSB) |
| Boot chain tampering | PCRLock multi-PCR binding (PCR 0-7), TPM NV index policy, PCR0 reconstruction |
| TPM key extraction (bus sniffing) | fTPM detection (no external bus), TPM bus encryption (CONFIG_TCG_TPM2_HMAC), dictionary attack lockout |
| DMA attack (Thunderbolt/PCIe) | IOMMU enforcement, pre-boot DMA protection |
| Kernel runtime attack (module/rootkit) | Kernel lockdown, module signature enforcement, CET shadow stack, SMAP |
| Physical debug attack (JTAG/DCI) | Debug interface lock, fused production part (via fwupd HSI / AMD HSTI) |
| Firmware tampering (SPI flash/replay) | SPI write protection, replay protection, anti-rollback (via fwupd HSI / AMD HSTI) |
| SMM attack (ring -2 rootkit) | SMM lock enforcement (via fwupd) |
| Cold boot attack (RAM dump) | Memory encryption (AMD SME/TSME, Intel TME) - informational, does not affect tier |
| Brute-force / key theft | TPM2 token with PIN, PCRLock binding, TOTP recovery fallback |

### Protection Tiers

`vanguard status` evaluates all mitigations and assigns a tier:

| Tier | Meaning |
|------|---------|
| PHYSICAL | All software and physical-attack mitigations active |
| HIGH | All software mitigations active (physical checks incomplete or not available) |
| WARNING | Some mitigations missing - reduced protection |
| CRITICAL | A core mitigation is broken - system may be compromised |
| LOW | No TPM2 token - passphrase only |

### PCR Coverage

| PCR | Name | Enforcement |
|-----|------|:-----------:|
| 0 | platform-code | Enforced |
| 1 | platform-config | Enforced |
| 2 | external-code | Enforced |
| 3 | external-config | Enforced |
| 4 | boot-loader-code | Enforced (multi-branch) |
| 5 | GPT partition table | Optional (`-l` flag) |
| 7 | secure-boot-policy | Enforced |
| 13 | sysexts | Unbound |
| 14 | shim-policy | Unbound |

The TOTP recovery seed is sealed to PCR 7 (Secure Boot state) in TPM NVRAM. If Secure Boot keys change (firmware update), the seed becomes inaccessible and is automatically re-provisioned via `vanguard recovery --auto-reseed`.

## Quick Start

```bash
# Build from source
git clone https://github.com/zaolin/vanguard
cd vanguard
make

# Check system protection status
sudo ./vanguard status

# Generate initramfs
sudo ./vanguard generate -o /boot/initramfs-linux.img

# Set up TPM2 PCRLock policy + enroll token
sudo vanguard enroll -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2 --with-pin

# Enable TOTP recovery (scan QR code with authenticator app)
sudo vanguard recovery --enable
```

For the full setup guide including partition layout, kernel command line, and firmware update handling, see [TPM2 Setup Guide](docs/tpm2-setup.md).

## Commands

| Command | Description |
|---------|-------------|
| `vanguard generate` | Generate an initramfs image |
| `vanguard update` | Update TPM2 PCRLock policy for a new UKI |
| `vanguard enroll` | Enroll TPM2 token on a LUKS device (runs update + systemd-cryptenroll) |
| `vanguard verify` | Verify TPM2 pcrlock setup (PCRs, NV index, LUKS token) |
| `vanguard status` | Show system protection status as a threat-model view |
| `vanguard recovery` | Manage TOTP-based boot recovery (`--enable`, `--show`, `--disable`, `--clean`, `--auto-reseed`) |
| `vanguard inspect` | Inspect contents of a generated initramfs |

See [Configuration](docs/configuration.md) for all CLI options and config file format.

## Architecture

Vanguard has a dual-binary design:

- **`cmd/vanguard/`** - CLI tool running on the build host, generates initramfs images
- **`init/`** - Init binary running inside the initramfs at boot (19-step sequence)
- **`internal/`** - Shared libraries: native Go TPM2 client, native Go LUKS, CPIO writer, compression, pcrlock integration

The init binary is statically linked (`CGO_ENABLED=0`) with zero runtime dependencies. LUKS unlock and TPM2 operations use native Go implementations - no `cryptsetup` or `tpm2-tools` needed at boot. The only external binaries in the initramfs are `lvm`, `systemd-udevd`/`udevadm`, and `dmsetup`.

## Requirements

**Build:** Go 1.25+, make

**Runtime (in initramfs):** lvm2, systemd-udevd, systemd-pcrlock (policy generation only)

**Optional:**
- systemd 262+ - enables the `io.systemd.PCRLock` Varlink interface
- fwupd 2.1.7+ - platform security checks via HSI, automatic firmware update coordination
- sbctl - Secure Boot file signature verification

A systemd unit (`vanguard-pcrlock-relock.service`) is shipped for automatic policy re-locking and recovery seed re-provisioning after firmware updates. See [TPM2 Setup Guide](docs/tpm2-setup.md#automatic-re-lock-after-firmware-update).

## Documentation

| Document | Description |
|----------|-------------|
| [TPM2 Setup](docs/tpm2-setup.md) | TPM2 enrollment, PCRLock policy, firmware update handling, recovery |
| [Configuration](docs/configuration.md) | CLI options, config file, all commands |
| [Boot Flow](docs/boot-flow.md) | Initramfs boot sequence (19 steps) |
| [Kernel Parameters](docs/kernel-parameters.md) | Supported kernel command line options |

## Testing

```bash
# QEMU test with software TPM (direct kernel boot, no UEFI)
./scripts/qemu-test.sh all-tpm

# Full UEFI test (OVMF non-secure + swtpm + UKI on ESP)
./scripts/qemu-test.sh all-uefi

# Full Secure Boot test (OVMF secboot + swtpm + signed UKI)
# First provision OVMF with self-generated keys:
./scripts/qemu-test.sh provision-ovmf
# Then run the full chain:
./scripts/qemu-test.sh all-secure

# Unit tests
go test ./internal/tpm/...    # TPM2 policy + recovery
go test ./internal/luks/...    # LUKS header parsing
go test ./cmd/vanguard/...     # Status, fwupd, sbctl, recovery
```

## License

MIT License - see [LICENSE](LICENSE) for details.