# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vanguard is a minimal, security-focused initramfs generator for Linux systems with full disk encryption. It creates lightweight boot images optimized for LUKS + LVM + TPM2 setups.

## Build Commands

```bash
make              # Build vanguard CLI with all embedded init binaries
make embed        # Build only the 4 init binary variants
make clean        # Remove build artifacts
make install      # Install to GOPATH/bin
```

The build produces a single `vanguard` binary containing 4 embedded init variants:
- `init` - Release (minimal output)
- `init-debug` - Debug mode (`-tags debug`)
- `init-strict` - Strict mode, token-only unlock (`-tags strict`)
- `init-debug-strict` - Both modes (`-tags "debug,strict"`)

## Testing

```bash
./scripts/qemu-test.sh all-tpm    # Full test cycle with software TPM
./scripts/qemu-test.sh build      # Build initramfs only
./scripts/qemu-test.sh disk       # Create test LUKS+LVM disk
./scripts/qemu-test.sh enroll-tpm # Enroll TPM2 token
./scripts/qemu-test.sh tpm        # Boot with TPM in QEMU
```

There are no Go unit tests - all testing uses QEMU integration tests with real disk images and software TPM.

## Architecture

### Two Execution Contexts

The codebase serves two distinct execution contexts:

1. **CLI (`cmd/vanguard/`)** - Runs on the host system to generate initramfs images and manage TPM policies
2. **Init (`init/`)** - Runs as PID 1 inside the initramfs during early boot

### Package Structure

```
cmd/vanguard/           # CLI entry point (kong framework)
├── generate.go         # Initramfs generation logic
├── update_policy.go    # TPM2 PCRLock policy updates
├── verify_pcrlock.go   # Policy verification
└── embed/              # Embedded init binaries (go:embed)

init/                   # Boot-time init (runs as PID 1)
├── main.go             # 19-step boot sequence orchestration
├── cryptsetup/         # LUKS unlock via cryptsetup binary (current default)
├── luks/               # Native LUKS2 decryption via anatol/luks.go + google/go-tpm (newer, not yet default)
├── bootlog/            # Boot event logging to /boot/.vanguard.log
├── switchroot/         # chroot and exec to real init
├── mount/              # Essential + root filesystem mounting
├── lvm/                # LVM volume activation
├── gpt/                # GPT partition autodiscovery
├── tui/                # Charmbracelet bubbletea boot UI
├── console/            # Early console setup
├── udev/               # Device manager integration
├── modules/            # Kernel module loading
├── vconsole/           # Keyboard/font configuration
├── fsck/               # Filesystem checking
├── resume/             # Hibernation resume
└── buildtags/          # Build-time feature flags

internal/               # Shared between CLI and init
├── config/             # TOML configuration parsing
├── pcrlock/            # TPM2 PCR policy management (systemd-pcrlock wrapper)
├── tpm/                # Native Go TPM2 operations (google/go-tpm tpmdirect API)
├── luks/               # LUKS device detection
├── firmware/           # Firmware collection and decompression
├── modules/            # Kernel module discovery
├── libs/               # Dynamic library dependency resolution
├── cpio/               # CPIO archive creation
├── compress/           # Compression (zstd, gzip, none)
└── fstab/              # /etc/fstab parsing
```

### Build Tag System

The init binary uses Go build tags to control behavior:

- `debug` tag: Enables verbose logging, disables TUI (logs to console instead)
- `strict` tag: Disables passphrase fallback when TPM2 token is present

Build tags are defined in `init/buildtags/` and checked at runtime throughout the init code.

### Boot Sequence

The init runs a 19-step boot sequence with 3 substeps (see `init/main.go`):
1. Console/filesystem setup
2. Device discovery (udev, modules, TPM)
3. LUKS unlock (TPM2 → PIN → Passphrase fallback)
4. LVM activation
5. Root mount and switch_root

Fatal errors halt boot. Non-fatal errors (e.g., /boot mount fails) log warnings and continue.

### LUKS Unlock Flow

`init/cryptsetup/` implements the unlock strategy (current default):
1. Scan `/sys/block` for LUKS devices
2. Try TPM2 token unlock first (with optional PIN)
3. Classify TPM errors (wrong PIN, PCR mismatch, lockout, etc.)
4. Fall back to passphrase prompt (3 attempts max, unless strict mode)

`init/luks/` + `internal/tpm/` provide a newer native Go implementation using `anatol/luks.go` and `google/go-tpm` (tpmdirect API), but `init/main.go` currently uses `init/cryptsetup/`.

### PCRLock Integration

`internal/pcrlock/` wraps systemd-pcrlock to:
- Configure PCR masks (disable PCR 15 for Vanguard measurements)
- Lock Secure Boot (PCR 7), GPT (PCR 5), UKI (PCR 4)
- Generate policy JSON with NV index
- Verify policy consistency

## Key Dependencies

- `github.com/alecthomas/kong` - CLI argument parsing
- `github.com/BurntSushi/toml` - Configuration file parsing
- `github.com/charmbracelet/bubbletea` - TUI framework for boot UI
- `github.com/klauspost/compress` - zstd compression
- `github.com/google/go-tpm` - Native TPM2 operations (tpmdirect API)
- `github.com/anatol/luks.go` - Native LUKS2 device handling
- `golang.org/x/sys` - Low-level syscalls for mount operations

## Static Compilation

Init binaries are statically compiled (`CGO_ENABLED=0`) with stripped symbols (`-ldflags "-s -w"`) for minimal size and no dynamic linking dependencies.
