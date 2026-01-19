#!/bin/bash
# QEMU test script for vanguard initramfs
# This script creates a test environment with LUKS + LVM and optional TPM

set -e

#=============================================================================
# Configuration
#=============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR="${PROJECT_DIR}/test"
DISK_RAW="${TEST_DIR}/test-disk.raw"
DISK_IMG="${TEST_DIR}/test-disk.qcow2"
INITRAMFS="${TEST_DIR}/initramfs.img"
DISK_SIZE="1G"
LUKS_PASS="testpass"
TPM_DIR="${TEST_DIR}/tpm"
TPM_SOCKET="${TEST_DIR}/swtpm.sock"

#=============================================================================
# Utility Functions
#=============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_deps() {
    local missing
    missing=()
    for cmd in qemu-system-x86_64 qemu-img cryptsetup pvcreate vgcreate lvcreate mkfs.ext4; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -ne 0 ]]; then
        error "Missing dependencies: ${missing[*]}"
    fi
}

setup_test_dir() {
    mkdir -p "${TEST_DIR}"
}

# Find a bootable kernel
find_kernel() {
    local kernel="${1:-}"
    if [ -n "${kernel}" ]; then
        if [ -f "${kernel}" ]; then
            realpath "${kernel}"
            return
        fi
        # Check if it was a relative path that we can resolve from PROJECT_DIR
        if [ -f "${PROJECT_DIR}/${kernel}" ]; then
            realpath "${PROJECT_DIR}/${kernel}"
            return
        fi
    fi
    for k in /boot/vmlinuz-* /boot/vmlinuz; do
        [ -f "$k" ] && realpath "$k" && return
    done
    return 1
}

#=============================================================================
# swtpm Functions
#=============================================================================

check_swtpm_deps() {
    command -v swtpm &>/dev/null || error "swtpm not found. Install swtpm package."
    /sbin/ldconfig -p 2>/dev/null | grep -q libtss2-tcti-swtpm || \
        error "libtss2-tcti-swtpm library not found."
}

init_swtpm_state() {
    info "Initializing swtpm state..."
    mkdir -p "${TPM_DIR}"
    rm -rf "${TPM_DIR:?}"/*
    command -v swtpm_setup &>/dev/null && swtpm_setup --tpmstate "${TPM_DIR}" --tpm2 --createek
}

start_swtpm() {
    command -v swtpm &>/dev/null || error "swtpm not found."

    # Kill any existing instance and clean up sockets
    pkill -f "swtpm socket.*${TPM_SOCKET}" 2>/dev/null || true
    sleep 0.3
    rm -f "${TPM_SOCKET}" "${TPM_SOCKET}.ctrl" 2>/dev/null || true

    info "Starting swtpm..."
    swtpm socket \
        --tpmstate dir="${TPM_DIR}" \
        --ctrl type=unixio,path="${TPM_SOCKET}" \
        --tpm2 \
        --flags not-need-init \
        --log level=5 >> "${TPM_DIR}/swtpm.log" 2>&1 &

    sleep 1
    [ -S "${TPM_SOCKET}" ] || { tail -20 "${TPM_DIR}/swtpm.log"; error "Failed to start swtpm"; }
    info "swtpm started at ${TPM_SOCKET}"
}

start_swtpm_for_enrollment() {
    info "Starting swtpm for enrollment..."
    rm -f "${TPM_SOCKET}" "${TPM_SOCKET}.ctrl" 2>/dev/null || true

    swtpm socket \
        --tpmstate dir="${TPM_DIR}" \
        --server type=unixio,path="${TPM_SOCKET}" \
        --ctrl type=unixio,path="${TPM_SOCKET}.ctrl" \
        --tpm2 \
        --flags startup-clear \
        --log level=5 >> "${TPM_DIR}/swtpm.log" 2>&1 &

    sleep 1
    [ -S "${TPM_SOCKET}" ] || error "Failed to start swtpm for enrollment"
}

stop_swtpm() {
    # Graceful shutdown if swtpm_ioctl available
    if command -v swtpm_ioctl &>/dev/null; then
        swtpm_ioctl --unix "${TPM_SOCKET}" --save permanent 2>/dev/null || true
        swtpm_ioctl --unix "${TPM_SOCKET}" --stop 2>/dev/null || true
    fi
    pkill -TERM -f "swtpm socket.*${TPM_SOCKET}" 2>/dev/null || true
    sleep 0.3
    rm -f "${TPM_SOCKET}" "${TPM_SOCKET}.ctrl" 2>/dev/null || true
    info "swtpm stopped"
}

#=============================================================================
# Build Functions
#=============================================================================

build_initramfs() {
    info "Building vanguard..."
    cd "${PROJECT_DIR}"
    make clean && make

    info "Generating initramfs (debug mode)..."
    ./vanguard generate -o "${INITRAMFS}" -c zstd -d

    # Replace the system fstab in initramfs with our test fstab
    info "Replacing fstab in initramfs with test fstab..."
    replace_initramfs_fstab

    info "Initramfs: ${INITRAMFS} ($(du -h "${INITRAMFS}" | cut -f1))"
}

build_initramfs_tui() {
    info "Building vanguard..."
    cd "${PROJECT_DIR}"
    make clean && make

    info "Generating initramfs (TUI mode)..."
    ./vanguard generate -o "${INITRAMFS}" -c zstd  # No -d flag = TUI mode

    # Replace the system fstab in initramfs with our test fstab
    info "Replacing fstab in initramfs with test fstab..."
    replace_initramfs_fstab

    info "Initramfs: ${INITRAMFS} ($(du -h "${INITRAMFS}" | cut -f1))"
}

replace_initramfs_fstab() {
    # Create test fstab matching the test disk layout
    local test_fstab="${TEST_DIR}/fstab"
    cat > "${test_fstab}" << 'FSTAB'
/dev/vg0/root  /      ext4  defaults  0 1
/dev/sda1      /boot  vfat  defaults  0 2
FSTAB

    # Extract initramfs, replace fstab, recompress
    local tmpdir
    tmpdir=$(mktemp -d)
    cd "${tmpdir}"

    # Detect compression and decompress
    if file "${INITRAMFS}" | grep -q "Zstandard"; then
        zstd -d < "${INITRAMFS}" | cpio -idm 2>/dev/null
    elif file "${INITRAMFS}" | grep -q "gzip"; then
        gzip -d < "${INITRAMFS}" | cpio -idm 2>/dev/null
    else
        cpio -idm < "${INITRAMFS}" 2>/dev/null
    fi

    # Replace fstab
    cp "${test_fstab}" "${tmpdir}/etc/fstab"

    # Recompress (use zstd to match original)
    find . -print0 | cpio --null -o -H newc 2>/dev/null | zstd -19 > "${INITRAMFS}"

    cd "${PROJECT_DIR}"
    rm -rf "${tmpdir}"
}

generate_pcrlock() {
    local pcrlock_bin=""
    command -v systemd-pcrlock &>/dev/null && pcrlock_bin="systemd-pcrlock"
    [ -z "$pcrlock_bin" ] && [ -f /usr/lib/systemd/systemd-pcrlock ] && \
        pcrlock_bin="/usr/lib/systemd/systemd-pcrlock"
    [ -z "$pcrlock_bin" ] && { warn "systemd-pcrlock not found"; return; }

    info "Generating pcrlock policy..."
    if sudo SYSTEMD_TPM2_DEVICE="swtpm:path=${TPM_SOCKET}" \
        "${pcrlock_bin}" make-policy --policy="${TEST_DIR}/pcrlock.json" --force; then
        sudo chown "$(id -u):$(id -g)" "${TEST_DIR}/pcrlock.json"
        info "pcrlock policy created"
        # Copy pcrlock.json to /boot on the test disk
        copy_pcrlock_to_boot
    else
        warn "pcrlock generation failed"
    fi
}

copy_pcrlock_to_boot() {
    [ -f "${TEST_DIR}/pcrlock.json" ] || { warn "pcrlock.json not found"; return; }
    [ -f "${DISK_IMG}" ] || { warn "Disk image not found"; return; }

    info "Copying pcrlock.json to /boot on test disk..."

    # We need to mount the boot partition from the qcow2 image
    # Convert to raw temporarily for mounting
    local tmpraw
    tmpraw=$(mktemp)
    qemu-img convert -f qcow2 -O raw "${DISK_IMG}" "${tmpraw}"

    local loop
    loop=$(sudo losetup -f --show "${tmpraw}")
    sudo partprobe "${loop}"; sleep 1

    local boot_part="${loop}p1"
    local mntdir
    mntdir=$(mktemp -d)

    sudo mount "${boot_part}" "${mntdir}"
    sudo cp "${TEST_DIR}/pcrlock.json" "${mntdir}/pcrlock.json"
    sudo umount "${mntdir}"
    rmdir "${mntdir}"

    sudo losetup -d "${loop}"

    # Convert back to qcow2
    qemu-img convert -f raw -O qcow2 "${tmpraw}" "${DISK_IMG}"
    rm -f "${tmpraw}"

    info "pcrlock.json copied to /boot"
}

#=============================================================================
# Disk Functions
#=============================================================================

create_test_disk() {
    if [ -f "${DISK_IMG}" ]; then
        warn "Test disk exists at ${DISK_IMG}"
        read -p "Recreate? [y/N] " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && return
        rm -f "${DISK_IMG}" "${DISK_RAW}"
    fi

    info "Creating disk image (${DISK_SIZE})..."
    qemu-img create -f raw "${DISK_RAW}" "${DISK_SIZE}"

    info "Setting up LUKS + LVM..."
    sudo "${SCRIPT_DIR}/helpers/create-disk.sh" "${DISK_RAW}" "${LUKS_PASS}"

    qemu-img convert -f raw -O qcow2 "${DISK_RAW}" "${DISK_IMG}"
    rm -f "${DISK_RAW}"
    info "Disk created: ${DISK_IMG}"
}

#=============================================================================
# TPM Enrollment
#=============================================================================

enroll_tpm() {
    check_swtpm_deps
    init_swtpm_state
    start_swtpm_for_enrollment

    info "Enrolling TPM2 token..."
    local pcrlock_arg=""
    if [ -f "${TEST_DIR}/pcrlock.json" ]; then
        pcrlock_arg="${TEST_DIR}/pcrlock.json"
        info "Using pcrlock policy: ${pcrlock_arg}"
    fi
    sudo "${SCRIPT_DIR}/helpers/enroll-tpm.sh" "${DISK_IMG}" "${DISK_RAW}" "${TPM_SOCKET}" "${LUKS_PASS}" "${pcrlock_arg}"

    stop_swtpm
    info "TPM enrollment complete"
}

#=============================================================================
# QEMU Functions
#=============================================================================

run_qemu() {
    local kernel
    kernel=$(find_kernel "${1:-}") || error "Kernel not found"
    [ -f "${INITRAMFS}" ] || error "Initramfs not found. Run: $0 build"
    [ -f "${DISK_IMG}" ] || error "Disk not found. Run: $0 disk"

    info "Starting QEMU..."
    qemu-system-x86_64 -m 2G -cpu host -enable-kvm \
        -kernel "${kernel}" -initrd "${INITRAMFS}" \
        -append "root=/dev/vg0/root console=ttyS0" \
        -device virtio-scsi-pci,id=scsi0 \
        -device scsi-hd,drive=hd0,bus=scsi0.0 \
        -drive file="${DISK_IMG}",format=qcow2,id=hd0,if=none \
        -nographic -no-reboot
}

run_qemu_quick() {
    local kernel
    kernel=$(find_kernel "${1:-}") || error "Kernel not found"
    [ -f "${INITRAMFS}" ] || build_initramfs

    info "Quick QEMU test (no disk)..."
    qemu-system-x86_64 -m 256M -cpu host -enable-kvm \
        -kernel "${kernel}" -initrd "${INITRAMFS}" \
        -append "console=ttyS0" -nographic -no-reboot
}

run_qemu_tpm() {
    local kernel
    kernel=$(find_kernel "${1:-}") || error "Kernel not found"
    [ -f "${INITRAMFS}" ] || error "Initramfs not found. Run: $0 build"
    [ -f "${DISK_IMG}" ] || error "Disk not found. Run: $0 disk"
    [ -d "${TPM_DIR}" ] || error "TPM state not found. Run: $0 enroll-tpm"

    start_swtpm
    trap stop_swtpm EXIT

    info "Starting QEMU with TPM..."
    qemu-system-x86_64 -machine q35 -m 2G -cpu host -enable-kvm \
        -kernel "${kernel}" -initrd "${INITRAMFS}" \
        -append "root=/dev/vg0/root console=ttyS0" \
        -device virtio-scsi-pci,id=scsi0 \
        -device scsi-hd,drive=hd0,bus=scsi0.0 \
        -drive file="${DISK_IMG}",format=qcow2,id=hd0,if=none \
        -chardev socket,id=chrtpm,path="${TPM_SOCKET}" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-crb,tpmdev=tpm0 \
        -nographic -no-reboot

    trap - EXIT
    stop_swtpm
}

#=============================================================================
# Cleanup
#=============================================================================

clean() {
    stop_swtpm 2>/dev/null || true
    info "Cleaning up..."
    rm -rf "${TEST_DIR}" "${PROJECT_DIR}/vanguard"
    info "Done"
}

#=============================================================================
# Main
#=============================================================================

case "${1:-}" in
    build)
        check_deps; setup_test_dir; build_initramfs ;;
    build-tui)
        check_deps; setup_test_dir; build_initramfs_tui ;;
    disk)
        check_deps; setup_test_dir; create_test_disk ;;
    run)
        run_qemu "${2:-}" ;;
    run-tui)
        run_qemu "${2:-}" ;;  # Same as run, uses TUI initramfs from build-tui
    quick)
        run_qemu_quick "${2:-}" ;;
    all)
        check_deps; setup_test_dir; build_initramfs; create_test_disk; run_qemu "${2:-}" ;;
    all-tui)
        check_deps; setup_test_dir; build_initramfs_tui; create_test_disk; run_qemu "${2:-}" ;;
    tpm)
        run_qemu_tpm "${2:-}" ;;
    tpm-tui)
        run_qemu_tpm "${2:-}" ;;  # Same as tpm, uses TUI initramfs from build-tui
    enroll-tpm)
        enroll_tpm ;;
    all-tpm)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs; run_qemu_tpm "${2:-}" ;;
    all-tpm-tui)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs_tui; run_qemu_tpm "${2:-}" ;;
    clean)
        clean ;;
    *)
        cat <<HELP
Vanguard QEMU Test Script

Usage: $0 <command> [kernel]

Build Commands:
  build              Build vanguard and generate initramfs (debug mode)
  build-tui          Build vanguard and generate initramfs (TUI mode)
  disk               Create LUKS+LVM test disk

Run Commands:
  run [kernel]       Run QEMU with test disk (debug mode)
  run-tui [kernel]   Run QEMU with test disk (TUI mode, use build-tui first)
  quick [kernel]     Quick test without disk
  all [kernel]       Full test: build, disk, run (debug mode)
  all-tui [kernel]   Full test: build-tui, disk, run (TUI mode)

TPM Commands:
  tpm [kernel]       Run QEMU with swtpm (debug mode)
  tpm-tui [kernel]   Run QEMU with swtpm (TUI mode, use build-tui first)
  enroll-tpm         Enroll TPM2 token (no PCR binding)
  all-tpm [kernel]   Full TPM test: disk, enroll, build, run (debug mode)
  all-tpm-tui [kernel] Full TPM test with TUI mode

Maintenance:
  clean              Remove all test files

Examples:
  $0 build
  $0 build-tui
  $0 all-tpm
  $0 all-tpm-tui
  $0 run /boot/vmlinuz
HELP
        exit 1
        ;;
esac
