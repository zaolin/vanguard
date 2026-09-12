package embed

import _ "embed"

// InitBinary contains the pre-built init binary (release mode, minimal output)
// Strict mode is always-on (no passphrase fallback without HOTP recovery)
//
//go:embed init
var InitBinary []byte

// InitDebugBinary contains the pre-built init binary (debug mode, verbose output)
// Strict mode is always-on (no passphrase fallback without HOTP recovery)
//
//go:embed init-debug
var InitDebugBinary []byte

// PersistentDiskRule is the vanguard udev rule that creates
// /dev/disk/by-uuid and /dev/disk/by-partuuid symlinks for physical
// partitions using the blkid builtin. The stock 60-persistent-storage.rules
// is not shipped (needs external ata_id/scsi_id binaries).
//
//go:embed 60-vanguard-persistent-disk.rules
var PersistentDiskRule []byte
