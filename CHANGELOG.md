# Changelog

## v0.3.0

_Released 08/19/2026 - LUKS header integrity binding, TOTP recovery fixes, unified config, and CI coverage pipeline_

### Features

- **LUKS Header Measurement (PCR 11)**
  - Vanguard's init now hashes the LUKS2 header and extends PCR 11 with the hash before disk unlock, binding the pcrlock policy to the on-disk LUKS header state
  - Detects offline LUKS header tampering: adding a backdoor keyslot, weakening KDF parameters, or changing the cipher breaks the PCR 11 policy and prevents disk unlock
  - Read-only measurement: vanguard never writes to the LUKS device during measurement
  - `vanguard update` creates a `.pcrlock` component file (`755-vanguard-luks-header.pcrlock`) with the expected PCR 11 extension digest
  - Auto-enabled when `--luks-device` is specified; use `--no-luks-header` to disable
  - Event log integration: writes CEL-JSON records to `/run/log/systemd/tpm2-measure.log` so `systemd-pcrlock make-policy` can predict PCR 11

- **Unified TOML Configuration**
  - `vanguard update` now accepts `--config /etc/vanguard.toml` to read `uki_path` and `luks_device` from the TOML config file
  - Eliminates the separate `/etc/vanguard/vanguard.env` file - all configuration in one place
  - CLI flags override TOML values when both are specified
  - `vanguard-pcrlock-relock.service` updated to use `--config` instead of `EnvironmentFile`

- **CI Coverage Pipeline**
  - Combined coverage from go tests and QEMU boot runs, merged via `gocovmerge`
  - Coverage badge in README (auto-updated by CI via `.github/coverage.json`)
  - CI status badges for all four workflows: lint, unit tests, coverage, secure boot
  - Coverage threshold: 34% combined

### Bug Fixes

- **TOTP recovery fails when RTC is wrong**
  - After firmware update, the RTC resets (often to epoch 0). The user's authenticator app generates codes using real current time, but vanguard validated against the broken RTC with only ±5min tolerance
  - Added `ValidateWithDrift` which also tries the reference timestamp (last boot time) with ±24h window (`WideSkew=2880`). Safe because the TOTP seed is TPM-protected

- **Only 1 TOTP attempt instead of 3 (TUI input conflict)**
  - `tui.Quit()` waited only 500ms for bubbletea to exit, then continued. If the TUI goroutine was still alive, it competed with `console.ReadPassword` for TTY input
  - Increased Quit timeout from 500ms to 2s; `ReadPassword` now re-opens `/dev/console` fresh instead of sharing the TUI's file descriptor

- **Only 1 PIN attempt instead of 3 (error classification)**
  - `PolicyAuthorizeNV` and `buildSuperPCRPolicySession` errors in `unsealWithPCRLock` were not classified through `classifyUnsealError`, so they were not `ErrPolicyFailed`
  - The PIN retry loop checked for `ErrPolicyFailed` and exited after 1 attempt. Now classifies all pcrlock errors with `usePCRLock=true`

- **PCR 11 missing from pcrlock policy**
  - `make-policy` validated the entire event log, including systemd's `sysinit`/`ready` phases on PCR 11. Their components were masked, causing "unrecognized measurements" and PCR 11 being dropped
  - Added `--location=756` to limit prediction window to the LUKS header component
  - Unmasked `850-sysinit.pcrlock` and `900-ready.pcrlock` so validation passes
  - Added `previouslyMaskedPolicies` cleanup to remove stale `/dev/null` symlinks
  - Added `eventlog-pcr11.pcrlock` variant for stale `uki.pcrlock` after initrd regeneration
  - Added `luks-header-eventlog.pcrlock` variant for the chicken-and-egg problem where vanguard update re-enrolls the TPM2 token, changing the LUKS header hash
  - Added `InjectLUKSHeaderPrediction` to post-process pcrlock.json with the new on-disk hash prediction
  - Fixed record search to use exclusion-based identification (systemd-pcrlock cel strips content from unrecognized records)

### Testing

- 30+ new test files across all packages
- swtpm-based integration tests for TPM operations (ExtendPCR, recovery, policy)
- QEMU boot coverage pipeline working on CI (18.5% from QEMU + 30.5% from go tests = 34.9% combined)
- Unit tests for LUKS header hashing (read-only verification, determinism, tamper detection)
- Unit tests for CEL-JSON event log writing (format, append mode, flock, error paths)
- Unit tests for pcrlock component file generation (format, masking, read-only)

### Documentation

- README rewritten with high-level focus, threat model table, CI badges
- `docs/tpm2-setup.md` updated for PCR 11 LUKS header binding, `--location` parameter, unified TOML config
- `docs/configuration.md` updated with `uki_path` and `luks_device` fields

---

## v0.2.0

_Released 08/10/2026 - Threat model status view, single-branch recovery, TPM injectable transport, CI/CD pipeline_

### Features

- **Threat-model status view**
  - 10 attack vectors (Evil Maid, Boot Chain, TPM Key Extraction, DMA, Kernel Runtime, Cold Boot, Brute-Force, Physical Debug, Firmware Tampering, SMM)
  - PHYSICAL/HIGH/WARNING/CRITICAL/LOW tiers
  - fwupd HSI + sbctl + HSTI integration
  - Borderless always-expanded view

- **Single-branch recovery policy**
  - Changed from 3-branch PolicyOR to single-branch PolicyPCR(PCR 7)
  - `--auto-reseed` for firmware update convergence
  - Shipped systemd unit `vanguard-pcrlock-relock.service`

- **TPM injectable transport**
  - `NewWithTransport()` in `internal/tpm/tpm.go`
  - swtpm test helper in `internal/tpm/swtpmtest/`

- **CI/CD pipeline**
  - 5 GitHub Actions workflows (unit-tests, lint, coverage, secure-boot-test, build-ci-image)
  - Dockerfile.ci with Ubuntu 25.04, Go, QEMU, swtpm, cryptsetup, systemd, ukify, efitools, sbsigntool, OVMF
  - QEMU boot coverage infrastructure with C wrapper, ext4 cover disk, `--init-binary` flag

---

## v0.1.0

_Released 08/08/2026 - Initial release_

### Features

- Minimal Go-based initramfs generator for LUKS + LVM + TPM2 systems
- Native LUKS2 header parsing (no cryptsetup binary dependency)
- TPM2 token unseal with pcrlock support (PolicyAuthorizeNV)
- TOTP-based boot recovery (TOTP seed sealed in TPM NVRAM, PCR 7 bound)
- PCRLock policy generation wrapping systemd-pcrlock
- GPT partition table binding (PCR 5)
- Secure Boot state binding (PCR 7)
- UKI multi-branch prediction (lock-pe, lock-uki, eventlog fallback)
- TUI boot interface with boot stage tracking
- Threat model status command with fwupd HSI, sbctl, AMD HSTI integration
- Boot logging (bootlog) with structured events
- Kernel module loading, vconsole configuration, fsck, hibernate resume
- zstd/gzip compression
- Debug build tag for verbose boot output