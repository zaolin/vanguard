#!/bin/bash
# Builds a minimal Linux kernel for QEMU testing from kernel.org source.
# The kernel includes support for: virtio-blk, virtio-scsi, ext4, FAT,
# TPM CRB, serial console, initramfs (gzip + zstd), PCI, ACPI.
#
# Usage: ./scripts/helpers/build-test-kernel.sh [output-path]
# Default output: testdata/kernel/bzImage

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_VER="6.14.7"
KERNEL_TARBALL="linux-${KERNEL_VER}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TARBALL}"
OUTPUT="${1:-${SCRIPT_DIR}/testdata/kernel/bzImage}"
CONFIG_PATH="${SCRIPT_DIR}/testdata/kernel/kernel.config"

if [ ! -f "${CONFIG_PATH}" ]; then
    echo "ERROR: kernel.config not found at ${CONFIG_PATH}"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

echo "[INFO] Downloading kernel ${KERNEL_VER}..."
curl -fsSL "${KERNEL_URL}" -o "${TMPDIR}/${KERNEL_TARBALL}"

echo "[INFO] Extracting..."
tar xf "${TMPDIR}/${KERNEL_TARBALL}" -C "${TMPDIR}"
cd "${TMPDIR}/linux-${KERNEL_VER}"

echo "[INFO] Applying config..."
cp "${CONFIG_PATH}" .config
make olddefconfig 2>&1 | tail -3

echo "[INFO] Building kernel (this takes several minutes)..."
make -j"$(nproc)" bzImage 2>&1 | tail -5

VMLINUZ="arch/x86/boot/bzImage"
if [ ! -f "${VMLINUZ}" ]; then
    echo "ERROR: bzImage not found after build"
    exit 1
fi

mkdir -p "$(dirname "${OUTPUT}")"
cp "${VMLINUZ}" "${OUTPUT}"
echo "[INFO] Kernel saved to ${OUTPUT}"
ls -lh "${OUTPUT}"