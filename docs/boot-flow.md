# Vanguard Boot Flow

This document describes the complete boot sequence executed by the Vanguard initramfs.

## Overview

Vanguard's init process is designed for systems with encrypted root filesystems using LUKS + LVM, with TPM2-based automatic unlocking. The boot sequence is carefully ordered to handle dependencies between components.

## Boot Sequence Overview

```mermaid
flowchart TD
    subgraph phase1["Phase 1: Early Initialization"]
        A[1. Console Setup] --> B[2. Mount Essential Filesystems]
        B --> C[3. Configure Vconsole]
    end

    subgraph phase2["Phase 2: Device Discovery"]
        D[4. Mount /boot Early] --> E[5. Init Boot Log]
        E --> F[6. Start udevd]
        F --> G[7. Load Kernel Modules]
        G --> H[8. Trigger udev Events]
        H --> I[9. Load TPM Modules]
        I --> J[10. Setup PCRLock]
    end

    subgraph phase3["Phase 3: Unlock Storage"]
        K[11. Unlock LUKS Devices] --> L[12. Trigger udev for dm-crypt]
        L --> M[13. Activate LVM]
        M --> N[14. Trigger udev for LVM]
    end

    subgraph phase4["Phase 4: Mount Root"]
        O[15. Try Hibernate Resume] --> P[16. Find Root Device]
        P --> Q[17. Filesystem Check]
        Q --> R[18. Mount Root]
        R --> S[19. Create LVM Symlinks]
    end

    subgraph phase5["Phase 5: Switch Root"]
        T[20. Cleanup udev] --> U[21. Close Boot Log]
        U --> V[22. Switch Root to init]
    end

    phase1 --> phase2
    phase2 --> phase3
    phase3 --> phase4
    phase4 --> phase5
```

## Phase 1: Early Initialization

### Step 1: Console Setup
- Opens `/dev/console` for read/write
- Falls back to `/dev/tty1` or `/dev/ttyS0` if unavailable
- Redirects stdout/stderr to console
- Suppresses kernel messages (printk level 0)

### Step 2: Mount Essential Filesystems

```mermaid
flowchart LR
    subgraph mounts["Essential Mounts"]
        A["/proc"] --> B["/sys"]
        B --> C["/dev"]
        C --> D["/run"]
    end
    
    subgraph optional["Optional Mounts"]
        E["/sys/kernel/security"]
        F["/sys/firmware/efi/efivars"]
    end
    
    mounts --> optional
```

| Mount Point | Type | Purpose |
|-------------|------|---------|
| `/proc` | procfs | Process info, cmdline |
| `/sys` | sysfs | Device tree |
| `/dev` | devtmpfs | Device nodes |
| `/run` | tmpfs | Runtime data |

### Step 3: Vconsole Configuration

```mermaid
flowchart TD
    A[Parse /etc/vconsole.conf] --> B{Keymap set?}
    B -->|Yes| C[loadkeys KEYMAP]
    B -->|No| D{Check cmdline}
    D -->|vconsole.keymap=| C
    D -->|No| E[Skip keymap]
    
    C --> F{Font set?}
    E --> F
    F -->|Yes| G[setfont FONT]
    F -->|No| H[Done]
    G --> H
```

**Critical:** Must happen before any password prompts for non-US keyboard support.

## Phase 2: Device Discovery

### Step 4: Mount /boot Early

The boot partition is mounted early to access `pcrlock.json` (if present) before LUKS unlock.

```mermaid
flowchart TD
    A[Start] --> B{boot= in cmdline?}
    B -->|Yes| C[Use specified device]
    B -->|No| D[Scan partitions]
    D --> E{Find pcrlock.json?}
    E -->|Yes| F[Use that partition]
    E -->|No| G[/boot not found]
    C --> H[Mount as FAT32]
    F --> H
    H --> I[Return success]
    G --> J[Return failure]
```

### Step 5: Init Boot Log

If `/boot` was mounted successfully, the boot log is initialized at `/boot/.vanguard.log`. All subsequent console output is also logged.

### Steps 6-10: Module Loading and TPM Setup

```mermaid
sequenceDiagram
    participant Init
    participant udevd
    participant Kernel
    participant TPM

    Init->>udevd: Start daemon
    Init->>Kernel: Load modules from /lib/modules
    Init->>udevd: Trigger events
    udevd->>Kernel: Request firmware
    Init->>udevd: Wait for settle (10s)
    Init->>Kernel: Load tpm_crb, tpm_tis, tpm_tis_core
    Kernel->>TPM: Initialize /dev/tpmrm0
    Init->>Init: Copy pcrlock.json to /var/lib/systemd/
```

## Phase 3: Unlock Encrypted Storage

### Step 11: LUKS Unlock Strategy

```mermaid
flowchart TD
    A[Scan /sys/block] --> B[Find LUKS devices]
    B --> D{Has TPM2 token?}
    
    D -->|Yes| E[Wait for /dev/tpmrm0]
    D -->|No| K
    
    E --> F{Token needs PIN?}
    F -->|No| G[cryptsetup open --token-only]
    F -->|Yes| H[Prompt for PIN]
    H --> I[cryptsetup open with PIN]
    
    G --> J{Success?}
    I --> J
    
    J -->|Yes| L[Device Unlocked]
    J -->|No| M[Log PCR values for debug]
    M --> K[Passphrase Fallback]
    
    K --> N[Prompt: Enter passphrase]
    N --> O{Correct?}
    O -->|Yes| L
    O -->|No, attempts < 3| N
    O -->|No, attempts = 3| P[HALT]
```

### Step 13: LVM Activation

```mermaid
flowchart TD
    A[pvscan --cache] --> B[vgscan]
    B --> C[vgchange -ay]
    C --> D[vgmknodes]
    D --> E[Create symlinks]
    E --> F["/dev/vg/lv → /dev/mapper/vg-lv"]
```

## Phase 4: Mount Root

### Step 15: Hibernate Resume

```mermaid
flowchart TD
    A{resume= in cmdline?} -->|No| B[Skip resume]
    A -->|Yes| C[Normalize LVM path]
    C --> D[Wait for device 5s]
    D --> E{Device exists?}
    E -->|No| B
    E -->|Yes| F[Get major:minor]
    F --> G{resume_offset= set?}
    G -->|Yes| H[Write to /sys/power/resume_offset]
    G -->|No| I[Write to /sys/power/resume]
    H --> I
    I --> J{Hibernation image?}
    J -->|Yes| K[Kernel restores memory]
    K --> L[Resume execution - never returns]
    J -->|No| B
    B --> M[Continue boot]
```

**Note:** Resume happens AFTER LUKS+LVM because swap is typically inside the encrypted volume. The LVM path `/dev/vg0/swap` is automatically normalized to `/dev/mapper/vg0-swap`.

### Step 16: Find Root Device

```mermaid
flowchart TD
    A[Start] --> B{root= in cmdline?}
    B -->|Yes| C[Use cmdline device]
    B -->|No| D{Root in /etc/fstab?}
    D -->|Yes| E[Use fstab device]
    D -->|No| F{GPT auto enabled?}
    F -->|Yes| G[Scan GPT tables]
    G --> H{Find root GUID?}
    H -->|Yes| I[Use discovered device]
    H -->|No| J[HALT: No root found]
    F -->|No| J
    
    C --> K[Normalize LVM path]
    E --> K
    I --> K
```

**Root GUID for x86-64:** `4f68bce3-e8cd-4db1-96e7-fbcaf984b709`

### Step 17: Filesystem Check

```mermaid
flowchart TD
    A{fsck disabled?} -->|Yes| B[Skip fsck]
    A -->|No| C[Find fsck binary]
    C --> D{Binary found?}
    D -->|No| B
    D -->|Yes| E{Filesystem type?}
    E -->|ext2/3/4| F[Run fsck.ext4 -y]
    E -->|xfs| G[Run xfs_repair -n]
    E -->|btrfs| B
    F --> H{Exit code}
    G --> H
    H -->|0: Clean| I[Continue]
    H -->|1: Corrected| I
    H -->|2: Reboot needed| I
    H -->|4+: Uncorrectable| J[Warning - continue anyway]
    J --> I
    B --> I
```

**Note:** btrfs check is skipped at boot time as it's not recommended. Filesystem check can be disabled with `vanguard.fsck=0` or `fsck.mode=skip`.

## Phase 5: Switch Root

### Steps 20-22: Cleanup and Handoff

```mermaid
sequenceDiagram
    participant Init
    participant udevd
    participant Kernel
    participant NewInit

    Init->>udevd: udevadm settle (5s)
    Init->>udevd: cleanup-db
    Init->>udevd: Stop daemon
    
    Init->>Init: Close boot log
    Init->>Kernel: Unmount /boot
    
    Init->>Kernel: Move /proc to /sysroot/proc
    Init->>Kernel: Move /sys to /sysroot/sys
    Init->>Kernel: Move /dev to /sysroot/dev
    Init->>Kernel: Move /run to /sysroot/run
    
    Init->>Kernel: chroot /sysroot
    Init->>NewInit: Try exec in order
    
    Note over NewInit: 1. /usr/lib/systemd/systemd
    Note over NewInit: 2. /lib/systemd/systemd
    Note over NewInit: 3. /sbin/init
    Note over NewInit: 4. /init
```

**Note:** Vanguard tries multiple init paths in order. The first one that exists and executes successfully is used.

## Error Handling

```mermaid
flowchart TD
    subgraph fatal["Fatal Errors → HALT"]
        A[No console]
        B[Essential mount fails]
        C[No LUKS devices found]
        D[LUKS unlock fails after 3 attempts]
        E[Root device not found]
        F[Root mount fails]
        G[No init found on root]
    end
    
    subgraph warn["Warnings → Continue"]
        H[/boot mount fails]
        I[LVM activation fails]
        J[fsck fails]
        K[Vconsole config fails]
        L[Resume fails]
        M[PCRLock setup fails]
    end
```

## Boot Logging

When ESP is mounted, events are logged to `/boot/.vanguard.log`:

```
2024-01-15T10:30:00Z BOOT_START
2024-01-15T10:30:00Z ESSENTIAL_MOUNTS status=ok
2024-01-15T10:30:00Z BOOT_MOUNTED status=ok
2024-01-15T10:30:01Z MODULES_LOADED count=15
2024-01-15T10:30:02Z PCRLOCK found=true
2024-01-15T10:30:03Z LUKS_UNLOCK device=/dev/sda2 method=tpm2 status=ok
2024-01-15T10:30:04Z LVM_ACTIVATE status=ok
2024-01-15T10:30:05Z ROOT_MOUNTED target=/sysroot device=/dev/vg0/root status=ok
2024-01-15T10:30:05Z SWITCHROOT target=/sysroot
```

## Debug Mode

Enable verbose output with: `vanguard generate -d -o /boot/initramfs-linux.img`

Debug output shows all boot steps:
```
vanguard: starting init
vanguard: mounting filesystems
vanguard: configuring vconsole
vanguard: loaded keymap us
vanguard: mounting /boot early
vanguard: starting udevd
...
```

## Complete Boot Timeline

```mermaid
gantt
    title Vanguard Boot Sequence
    dateFormat X
    axisFormat %s
    
    section Phase 1
    Console Setup           :a1, 0, 1
    Mount Filesystems       :a2, after a1, 1
    Vconsole Config         :a3, after a2, 1
    
    section Phase 2
    Mount /boot             :b1, after a3, 1
    Init Boot Log           :b2, after b1, 1
    Start udevd             :b3, after b2, 1
    Load Modules            :b4, after b3, 2
    Trigger udev            :b5, after b4, 3
    Load TPM Modules        :b6, after b5, 1
    Setup PCRLock           :b7, after b6, 1
    
    section Phase 3
    Unlock LUKS             :c1, after b7, 3
    udev dm-crypt           :c2, after c1, 2
    Activate LVM            :c3, after c2, 2
    udev LVM                :c4, after c3, 2
    
    section Phase 4
    Try Resume              :d1, after c4, 1
    Find Root               :d2, after d1, 1
    fsck                    :d3, after d2, 2
    Mount Root              :d4, after d3, 1
    Create LVM Symlinks     :d5, after d4, 1
    
    section Phase 5
    Cleanup udev            :e1, after d5, 1
    Close Boot Log          :e2, after e1, 1
    Switch Root             :e3, after e2, 1
```
