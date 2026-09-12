# Changelog

## Unreleased

### Features

- **Recovery switched from TOTP to HOTP (RFC 4226) — no clock dependency**
  - The initramfs has no trustworthy clock: the RTC can be reset (dead CMOS battery, firmware update) and there is no network for NTP. TOTP recovery therefore depended on a TPM-stored reference timestamp plus a drift ladder and a two-code time-resync fallback, which proved fragile in practice.
  - HOTP is counter-based: the counter is persisted in TPM NV `0x01C30003` and advanced past the matched position on every successful code. RTC state, timezone, NTP, drift, and the entire reference-timestamp/anchor machinery are gone.
  - 8-digit codes, HMAC-SHA256, lookahead window of 4 counters (~1.5×10⁻⁷ per boot). Per-boot cap of 3 attempts plus a persistent failure counter (`MaxFailCount=10`) that locks recovery until a successful disk unlock resets it — bounding cross-boot online guessing.
  - The seed remains at `0x01C30001` under the PCR 7 (Secure Boot state) policy; the new state index (counter + fail count) is bound by the SAME PCR 7 policy — a live-USB boot can neither read nor reset the counter, so the failed-attempt cap and counter position cannot be rolled back.
  - **Re-enrollment required on upgrade:** an old TOTP seed has no state index and recovery fails closed until `vanguard recovery --enable` is re-run and the new `otpauth://hotp` QR is scanned with an HOTP-capable app (Aegis, FreeOTP, KeePassXC, Bitwarden, ...).
  - `vanguard recovery --show`/`--check` display the counter and fail-count state; a successful disk unlock resets the fail count.
  - QEMU scenario `all-tpm-recovery` now enrolls a real seed over swtpm and feeds a computed HOTP code end-to-end.
- **Smarter TOTP clock-drift recovery**
  - Reference timestamp is refreshed forward-only on every successful TPM-token boot, keeping the drift anchor fresh after long power-offs
  - Validation ladder: RTC ±90s → RTC ±5min / reference ±24h → two-code time resync: the user enters two consecutive authenticator codes and the real time is recovered by scan, even when the RTC is off by years and the reference is stale
  - Recovery persists the validated time base (never the raw RTC), with fallback to timestamp index recreation when the index is missing — and the validated anchor is re-applied after recreation
- **`root=UUID=` / `root=PARTUUID=` support** — resolved via `/dev/disk/by-*` symlinks created by a new builtin-only udev rule (`60-vanguard-persistent-disk.rules`); the stock rule creating these links is not shipped because it requires external ata_id/scsi_id binaries

### Fixed

- **`vanguard recovery --auto-reseed` destroyed the shared timestamp index and could fake success**
  - Root cause 1: temp-seed staging and cleanup used the composite `DefineRecoveryNVSpace`/`UndefineRecoveryNVSpace`, which also delete/recreate the shared timestamp index (0x01C30002) — every "successful" full reseed left the system with a live seed and NO timestamp index (the exact broken state observed on a live machine: seed present, timestamp missing, relock service dead)
  - Root cause 2: the swap undefined the old seed before the new one was confirmed at the primary index; on failure it printed a warning and returned success, stranding the new seed at the temp index (0x01C30101) with recovery silently broken — and the next `--auto-reseed` no-opped because the primary index was missing
  - Root cause 3: any seed-read failure (transport glitch, session error) was misdiagnosed as "PCR 7 changed" and triggered the destructive reseed even when the enrollment was healthy
  - Fix: split seed-only NV primitives (`DefineSeedNVIndex`/`WriteSeedOnly`/`UndefineSeedNVSpace`) that never touch the timestamp index; the reseed swap stages seed-only, writes the pending URI before destroying anything, returns hard errors instead of fake success, preserves the old reference timestamp across the swap, and detects stranded temp seeds on the next run
  - Fix: seed-read errors are now classified — `ErrSeedPCRMismatch` (genuine policy failure, the only reseed trigger) vs `ErrSeedReadTransient` (transport/session, never reseeds); TPM response codes are canonicalized (session/handle index bits masked) before comparison, which the previous direct comparison silently got wrong
  - Diagnosis order fixed: a missing timestamp index no longer masquerades as an unreadable seed (seed-only read is now the first diagnostic, so a repairable state is repaired without touching the seed)
- **Device nodes in generated initramfs had major/minor 0:0**
  - cavaliergopher/cpio v1.0.1 never serializes the SVR4 devmajor/devminor/rmajor/rminor header fields, so `dev/console`, `dev/null`, `dev/zero`, `dev/tty` were created as unusable (0,0) nodes by the kernel's initramfs parser — guaranteed boot failure on kernels that do not auto-mount devtmpfs
  - The generator now patches the device-number fields into the header (regression-tested against raw archive bytes), and the init binary mknods `/dev/console` + `/dev/null` as a last-resort fallback
- **PCR 11 status false-positive (CRITICAL tier on healthy systems)**
  - Live PCR 11 legitimately diverges from the policy after unlock (systemd post-unlock extensions); `vanguard status`/`verify`/`update` now verify the actual security property — the on-disk LUKS header digest against the enrollment-time component digests (`755-vanguard-luks-header.pcrlock.d/`)
  - PCR DETAILS table shows header digest comparison plus the live PCR 11 value, annotated
- **NV index extraction from `tpm2_pcrlock_nv` blobs** — unified parser (offset-2 spec-compliant + offset-0 legacy, pcrlock range validation) shared across the boot path and host tools; the previous host-side parser read at the wrong offset with no validation, which could feed a garbage index into NV cleanup and undefine the real token index
- **Pre-auth LUKS2 header parsing** — hdr_len is now bounds-checked in all readers (was unbounded in two paths → kernel-panic DoS in the initramfs from a corrupt/hostile header) and header reads loop to completion (single `Read` could short-read, silently hashing a truncated header)
- **Corrupt-header hardening in the native LUKS implementation**
  - LUKS2 key-area key_size validated before argon2 (was unbounded → multi-GB allocation) and segment sector_size validated as 512/4096 (was reachable as 0 → division-by-zero panic in PID 1)
  - LUKS1 keyslot iteration counts out of range now refuse the slot with a clear error instead of silently capping (capping altered the KDF output and made every correct passphrase fail); LUKS1 luksmeta token payload length bounded (was up to 4 GiB from a crafted header) with 64-bit offset math
- **GPT parser hardening** — partition entry size and count validated before allocation from the untrusted header
- **`vanguard enroll --verbose`** passed `-V` (version flag) to the re-exec'd `vanguard update` instead of `-v`
- **Header binding check** continues across LUKS devices when one device errors (an error on device 1 no longer masks a tampered header on device 2)
- **udevadm reload** now resolves the udevadm path the same way as the udevd start path — a hardcoded first-entry path silently skipped the db_persist rule reload on setups where only /sbin/udevadm exists, dropping /dev/mapper symlinks at switch_root
- Recovery TOTP validation re-reads the clock per attempt (a frozen `now` pushed users with a good RTC into the two-code flow after ~90s of fumbling); the two-code time resync retries once so a single mistyped digit does not end a recoverable boot
- Missing recovery timestamp index is a silent no-op for the boot-time refresh (was logging a failure on every boot of systems without recovery)
- `vanguard generate -o`/`-c` can now be supplied via the config file (`output`/`compression` keys work without the CLI flag)
- File-descriptor leak on LUKS header parse error paths in the native LUKS open path

### Changed

- Shared enforcement semantics (`pcrlock.IsEnforcedValues`) for `vanguard status` and `vanguard verify`
- `make ci` now runs tests with `-race` and gained a `lint` target matching the lint workflow; golangci-lint config added (`.golangci.yml`, v2 schema)
- Removed dead code: legacy unlock path, unused NV helpers, status collapse plumbing; shrank `GetLUKS2Info` to the fields the token finder actually uses
- Deleted unused CI collateral: build-ci-image workflow and Dockerfile.ci (consumed by nothing)
- QEMU test infrastructure: new `all-tpm-recovery` scenario with real swtpm-based TOTP recovery enrollment (`VANGUARD_TPM_SOCKET`, `VANGUARD_TEST_SKIP_VERIFY` host-side test env vars) validating the full recovery flow end-to-end

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