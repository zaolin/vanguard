#!/bin/bash
# Downloads a pre-built kernel for QEMU testing.
# Tries Fedora's kernel RPM first, then PXE images, then kernel.org source build.
set -e

DEST="${1:-test/vmlinuz}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$(dirname "${SCRIPT_DIR}/${DEST}")"

echo "[INFO] Downloading test kernel..."

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

# Method 1: Fedora PXE boot image (simplest, pre-built)
echo "  Trying Fedora PXE images..."
FEDORA_PXE="https://download.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os/images/pxeboot/vmlinuz"
if curl -fsSL "${FEDORA_PXE}" -o "${SCRIPT_DIR}/${DEST}" 2>/dev/null; then
    echo "[INFO] Kernel saved to ${SCRIPT_DIR}/${DEST}"
    ls -lh "${SCRIPT_DIR}/${DEST}"
    exit 0
fi

# Method 2: Fedora kernel RPM
echo "  RPM extraction..."
KERNEL_VER="6.12.4-100.fc40.x86_64"
KERNEL_RPM="https://download.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os/Packages/k/kernel-core-${KERNEL_VER}.rpm"
if curl -fsSL "${KERNEL_RPM}" -o "${TMPDIR}/kernel.rpm" 2>/dev/null; then
    cd "${TMPDIR}"
    if rpm2cpio kernel.rpm 2>/dev/null | cpio -idmv 2>/dev/null; then
        VMLINUZ=$(find . -name "vmlinuz*" -type f | head -1)
        if [ -n "${VMLINUZ}" ]; then
            cp "${VMLINUZ}" "${SCRIPT_DIR}/${DEST}"
            echo "[INFO] Kernel saved to ${SCRIPT_DIR}/${DEST}"
            ls -lh "${SCRIPT_DIR}/${DEST}"
            exit 0
        fi
    fi
fi

# Method 3: Build from kernel.org source with minimal config
echo "  Building from kernel.org source..."
KERNEL_VER="6.14.7"
KERNEL_TARBALL="linux-${KERNEL_VER}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TARBALL}"

if ! curl -fsSL "${KERNEL_URL}" -o "${TMPDIR}/${KERNEL_TARBALL}" 2>/dev/null; then
    echo "[ERROR] Failed to download kernel source"
    exit 1
fi

cd "${TMPDIR}"
tar xf "${KERNEL_TARBALL}"
cd "linux-${KERNEL_VER}"

# Minimal kernel config for QEMU + initramfs + virtio + TPM + serial
cat > .config << 'KCONFIG'
CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_RD_GZIP=y
CONFIG_RD_ZSTD=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_SCSI=y
CONFIG_SCSI=y
CONFIG_SCSI_LOWLEVEL=y
CONFIG_BLK_DEV_SD=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_PRINTK=y
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
CONFIG_EXT4_FS=y
CONFIG_VFAT_FS=y
CONFIG_FAT_FS=y
CONFIG_NLS=y
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_ISO8859_1=y
CONFIG_NLS_UTF8=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_TMPFS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_SYSCTL=y
CONFIG_DEVPTS_MULTIPLE_INSTANCES=y
CONFIG_UNIX=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_PACKET=y
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
CONFIG_TCG_TPM=y
CONFIG_TCG_TIS=y
CONFIG_TCG_TIS_CORE=y
CONFIG_TCG_CRB=y
CONFIG_TCG_TPM2_HMAC=y
CONFIG_SECURITYFS=y
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFI_VARS=y
CONFIG_PARTITION_ADVANCED=y
CONFIG_EFI_PARTITION=y
CONFIG_MSDOS_PARTITION=y
KCONFIG

make olddefconfig 2>/dev/null
make -j"$(nproc)" bzImage 2>&1 | tail -5

VMLINUZ="arch/x86/boot/bzImage"
if [ -f "${VMLINUZ}" ]; then
    cp "${VMLINUZ}" "${SCRIPT_DIR}/${DEST}"
    echo "[INFO] Kernel built and saved to ${SCRIPT_DIR}/${DEST}"
    ls -lh "${SCRIPT_DIR}/${DEST}"
    exit 0
fi

echo "[ERROR] Failed to obtain a test kernel"
exit 1