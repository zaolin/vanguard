#!/bin/bash
# Helper script for creating LUKS+LVM test disk (runs as root)
set -e

DISK_RAW="$1"
LUKS_PASS="$2"

LOOP=$(losetup -f --show "${DISK_RAW}")
cleanup() {
    set +e
    umount /dev/vg0/root 2>/dev/null
    umount "${LOOP}p1" 2>/dev/null
    cryptsetup close test-crypt 2>/dev/null
    vgchange -an vg0 2>/dev/null
    losetup -d "$LOOP" 2>/dev/null
}
trap cleanup EXIT

# Create ESP partition (FAT32) and LUKS partition
parted -s "$LOOP" mklabel gpt \
    mkpart ESP fat32 1MiB 101MiB \
    set 1 esp on \
    mkpart luks 101MiB 100%
partprobe "$LOOP"; sleep 1

BOOT_PART="${LOOP}p1"
LUKS_PART="${LOOP}p2"

# Format /boot as FAT32 (ESP)
mkfs.vfat -F 32 -n ESP "$BOOT_PART"

# Setup LUKS + LVM on second partition
echo -n "${LUKS_PASS}" | cryptsetup luksFormat --type luks2 "$LUKS_PART" -
echo -n "${LUKS_PASS}" | cryptsetup open "$LUKS_PART" test-crypt -

pvcreate /dev/mapper/test-crypt
vgcreate vg0 /dev/mapper/test-crypt
lvcreate -l 100%FREE -n root vg0
mkfs.ext4 -q /dev/vg0/root

# Mount root and boot
MNTDIR=$(mktemp -d)
mount /dev/vg0/root "$MNTDIR"
mkdir -p "$MNTDIR"/{bin,sbin,etc,proc,sys,dev,run,var,tmp,lib,lib64,boot}
mount "$BOOT_PART" "$MNTDIR/boot"

# Install busybox
BB=$(which busybox)
cp "$BB" "$MNTDIR/bin/busybox"
for cmd in sh mount umount ls cat echo sleep; do ln -sf busybox "$MNTDIR/bin/$cmd"; done

# Copy required libraries for dynamically-linked busybox
# Get the interpreter from the ELF header
INTERP=$(patchelf --print-interpreter "$BB" 2>/dev/null || readelf -l "$BB" | grep 'interpreter:' | sed 's/.*: \(.*\)]/\1/')
if [ -n "$INTERP" ] && [ -f "$INTERP" ]; then
    cp "$INTERP" "$MNTDIR$INTERP"
fi

# Copy required shared libraries
for lib in $(ldd "$BB" 2>/dev/null | grep -o '/[^ ]*' | sort -u); do
    if [ -f "$lib" ]; then
        LIBDIR=$(dirname "$lib")
        mkdir -p "$MNTDIR$LIBDIR"
        cp "$lib" "$MNTDIR$lib"
    fi
done

cat > "$MNTDIR/init" << 'INITSCRIPT'
#!/bin/sh
# Mount only if not already mounted (switchroot may have moved these)
grep -q ' /proc ' /proc/mounts 2>/dev/null || mount -t proc proc /proc
grep -q ' /sys ' /proc/mounts 2>/dev/null || mount -t sysfs sys /sys
grep -q ' /dev ' /proc/mounts 2>/dev/null || mount -t devtmpfs dev /dev
echo "Test rootfs ready"; exec /bin/sh
INITSCRIPT
chmod +x "$MNTDIR/init"

# Create fstab with both root and boot entries
# Use /dev/sda1 and /dev/sda2 as that's how QEMU will expose the disk
cat > "$MNTDIR/etc/fstab" << 'FSTAB'
/dev/vg0/root  /      ext4  defaults  0 1
/dev/sda1      /boot  vfat  defaults  0 2
FSTAB

umount "$MNTDIR/boot"
umount "$MNTDIR"; rmdir "$MNTDIR"
lvchange -an vg0/root; vgchange -an vg0
cryptsetup close test-crypt
losetup -d "$LOOP"; trap - EXIT
