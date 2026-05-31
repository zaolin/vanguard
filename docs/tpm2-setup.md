# TPM2 Setup Guide

This guide covers setting up TPM2-based automatic disk encryption unlocking with Vanguard.

## Overview

Vanguard uses a **native Go TPM2 stack** (`internal/tpm/`) for LUKS token unsealing. No external TPM tools are needed at runtime. The TPM chip stores the LUKS key sealed to Platform Configuration Register (PCR) values via PCRLock policy, ensuring the disk can only be unlocked when the system is in a known-good state.

```mermaid
flowchart LR
    A[Boot] --> B[TPM2 validates PCRs]
    B --> C{PCRs match?}
    C -->|Yes| D[Release key]
    C -->|No| E[Deny access]
    D --> F[Unlock LUKS]
    E --> G[Passphrase fallback]
```

## Prerequisites

### Required Packages
- `systemd` (version 251+)
- `tpm2-tss`
- `systemd-pcrlock` (at `/lib/systemd/systemd-pcrlock` or `/usr/lib/systemd/systemd-pcrlock`)

### System Requirements
- TPM 2.0 chip (hardware or firmware-based)
- UEFI Secure Boot (recommended)
- LUKS2 encrypted partition

### Verify TPM is Available

```bash
# Check for TPM device
ls -la /dev/tpm*

# Expected output:
# crw-rw---- 1 root root 10, 224 /dev/tpm0
# crw-rw---- 1 root root 253, 65536 /dev/tpmrm0

# Check TPM capabilities
tpm2_getcap properties-fixed
```

## PCRLock Policy

PCRLock provides fine-grained control over which boot measurements are validated using **predicted values** rather than current values. Vanguard's policy creates **multi-branch PCR predictions** (PolicyOR) where multiple PCR values are accepted, enabling firmware variation handling.

### Understanding PCRs

| PCR | Contents | Enforced | Notes |
|-----|----------|:--------:|-------|
| 2 | External code | ✓ Enforced (2 branches) | Option ROMs |
| 3 | External config | ✓ Enforced (2 branches) | |
| 4 | Boot loader code (UKI) | ✓ Enforced (up to 4 branches) | Multi-branch handles firmware variance |
| 5 | GPT partition table | Optional (`-l` flag) | Auto-enabled with `--luks-device` |
| 7 | Secure Boot state | ✓ Enforced (up to 2 branches) | Primary security PCR |
| 13 | sysexts | — Unbound (all-zeros) | |
| 14 | shim-policy | — Unbound (all-zeros) | |

**Unbound PCRs** (13, 14) appear in the policy as all-zeros because no measurements are made. They don't affect unlock — they're placeholders.

### PCR 4 Multi-Branch Prediction

PCR 4 (boot-loader-code) uses **PolicyOR** with up to 4 predicted values covering firmware event variations:

1. Current kernel measurement from `lock-pe`
2. Current kernel measurement from `lock-uki`  
3. Event log extraction for currently-booted kernel
4. PE fallback path measurement

This means PCR 4 won't prevent unlock unless the UKI itself has been tampered with — legitimate firmware variations are handled by the multi-branch policy.

### Secure Boot (PCR 7)

PCR 7 is the most security-critical PCR. It measures the Secure Boot state:

- `0x8E09...` = Secure Boot enabled with valid signed boot chain
- `0x940A...` = Alternative valid state (varies by firmware)

**Without PCR 7 in the policy, a compromised Secure Boot state would still allow disk unlock.** Run `vanguard status` to verify PCR 7 is present and matching.

### GPT Partition Table Binding (PCR 5)

When `--luks-device` (`-l`) is specified, Vanguard automatically enables GPT partition table binding:

**Benefits:**
- Validates correct disk identity (partition layout + GUIDs)
- Prevents attacks using a different disk with same UKI

**Caveats:** Partition changes break unlock — re-run `vanguard update -l <device>` after.

## Setup Workflow

```mermaid
flowchart TD
    A[1. Generate PCRLock Policy] --> B[2. Enroll TPM2 Token]
    B --> C[3. Generate Initramfs]
    C --> D[4. Reboot and Test]
    D --> E[5. Verify with Status]
```

### Step 1: Generate PCRLock Policy

```bash
# Basic policy (PCRs 2, 3, 4, 7)
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi

# With GPT binding (adds PCR 5)
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2

# With old NV index cleanup
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2 -c
```

This creates `<uki-path>.pcrlock.json` (e.g., `/boot/EFI/Gentoo/kernel.pcrlock.json`).

### Step 2: Enroll TPM2 Token

```bash
sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto \
  --tpm2-with-pin=yes \
  --tpm2-pcrlock=/boot/EFI/Gentoo/kernel.pcrlock.json \
  /dev/nvme0n1p2
```

### Step 3: Generate Initramfs

```bash
sudo vanguard generate -o /boot/initramfs-linux.img
```

### Step 4: Reboot and Test

```bash
sudo reboot
```

### Step 5: Verify Status

```bash
sudo vanguard status
```

Expected output:
```
  PROTECTION TIER: █████████████  HIGH
╭─ LUKS2  /dev/nvme0n1p2 ────────╮
│  Token: systemd-tpm2 PIN pcrlock│
│  NV:    0x1b8225b               │
╰─────────────────────────────────╯
╭─ TPM 2.0 ───────────────────────╮
│  Device: /dev/tpmrm0 available  │
╰─────────────────────────────────╯
╭─ BOOT INTEGRITY ────────────────╮
│  NV: 0x1b8225b present on TPM   │
│  ✓ PCR 2  external-code         │
│  ✓ PCR 3  external-config       │
│  ✓ PCR 4  boot-loader-code      │
│  ✓ PCR 7  secure-boot-policy    │
╰─────────────────────────────────╯
```

## Native Go TPM Stack

Vanguard's init binary uses **zero external TPM dependencies** at runtime:

| Component | Implementation |
|-----------|---------------|
| TPM communication | `google/go-tpm` via `tpmdirect` API |
| Sealed key unseal | Native PolicyPCR + PolicyAuthorizeNV (pcrlock) |
| PIN derivation | PBKDF2-HMAC-SHA256 with salt from LUKS token |
| SRK management | Transient creation, persistent handle, or tpm2_srk data |
| LUKS unlock | Native Go LUKS v1/v2 (`internal/luks/`) — no libcryptsetup |

All crypto is handled in-process. The only binaries included in the initramfs are `lvm`, `systemd-udevd`/`udevadm`, and `dmsetup`.

## Verify Policy

Verify the TPM, NV index, and LUKS token are synchronized:

```bash
# Basic verification (NV Index + PCR values)
sudo vanguard verify -p /boot/EFI/Gentoo/kernel.pcrlock.json

# With LUKS token validation
sudo vanguard verify -p /boot/EFI/Gentoo/kernel.pcrlock.json -l /dev/nvme0n1p2
```

Three checks run:
1. **NV Index sync** — TPM NV index auth policy + size match policy file
2. **PCR validation** — Current PCR values against policy expectations
3. **LUKS token** (with `-l`) — Token references correct NV index + enforces pcrlock

## Updating Kernel/UKI

When updating the kernel, update the PCRLock policy **before** booting the new kernel:

```mermaid
sequenceDiagram
    participant User
    participant Vanguard
    participant System
    
    User->>Vanguard: vanguard update (new UKI)
    Vanguard->>System: Create multi-branch policy
    User->>System: Install new UKI
    User->>System: Reboot
    System->>System: Boot new UKI
    System->>System: Validate against policy (PolicyOR)
    System->>System: Unlock successful
```

### Update Workflow

```bash
# 1. Update policy BEFORE installing new kernel
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2

# 2. Re-enroll token with updated policy
sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto \
  --tpm2-with-pin=yes \
  --tpm2-pcrlock=/boot/EFI/Gentoo/kernel.pcrlock.json \
  /dev/nvme0n1p2

# 3. Install the new kernel/UKI
# (distribution-specific commands)

# 4. Verify
sudo vanguard status

# 5. Reboot
sudo reboot
```

Vanguard creates up to 4 predicted values for PCR 4, so the old kernel can still unlock the disk until the new kernel is booted.

## NV Index Cleanup

When `--cleanup` (`-c`) is specified, old unused pcrlock NV indices are removed from the TPM:

```bash
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2 -c
```

Vanguard keeps the current policy NV index and the LUKS token's NV index, removing everything else in the pcrlock range (`0x01800000`–`0x01BFFFFF`).

## Troubleshooting

### TPM Unlock Fails — PCR Mismatch

**Symptom:** Boot falls back to passphrase with TPM error.

**Debug:** With debug mode (`-d`), Vanguard logs PCRs and current values to the boot log at `/boot/.vanguard.log`.

**Solution:**
```bash
# Check current status
sudo vanguard status

# Regenerate policy and re-enroll
sudo vanguard update -u /boot/EFI/Gentoo/kernel.efi -l /dev/nvme0n1p2
sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto \
  --tpm2-with-pin=yes \
  --tpm2-pcrlock=/boot/EFI/Gentoo/kernel.pcrlock.json \
  /dev/nvme0n1p2
```

### TPM Device Not Found

**Symptom:** TPM not available, boot uses passphrase.

**Check:**
```bash
lsmod | grep tpm     # Should show tpm_crb, tpm_tis, tpm_tis_core
ls -la /dev/tpm*     # Should show /dev/tpm0 and /dev/tpmrm0
```

Vanguard loads `tpm_crb`, `tpm_tis`, and `tpm_tis_core` modules automatically.

### PIN Prompt Fails

**Symptom:** Incorrect PIN errors, lockout.

**Check:** TPM lockout status with `vanguard status`.

**Solution:** Wait for lockout recovery period (shown in boot TUI), then re-enter correct PIN.

## Recovery

Always maintain a passphrase slot for emergency recovery:

```bash
# Add passphrase slot
sudo cryptsetup luksAddKey /dev/nvme0n1p2

# Verify slots exist
sudo cryptsetup luksDump /dev/nvme0n1p2 | grep "Key Slot"
```
