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
TPM_PIN="1234"  # PIN for TPM-protected unlock
TPM_DIR="${TEST_DIR}/tpm"
TPM_SOCKET="${TEST_DIR}/swtpm.sock"

# Console size simulation (rows cols)
# Default to 128x48 (approx 1024x768 standard console) if not set
CONSOLE_SIZE="${CONSOLE_SIZE:-48 128}"

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
    # For PCRLock we need to preserve NV indexes - use --not-overwrite
    # Only clear TPM state if explicitly requested via environment variable
    if [ "${CLEAR_TPM_STATE:-1}" = "1" ]; then
        info "Clearing existing TPM state (CLEAR_TPM_STATE=1)..."
        rm -rf "${TPM_DIR:?}"/*
    else
        info "Preserving existing TPM state..."
    fi
    # Use custom profile for TPM 2.0 with PolicyAuthorizeNV (required for PCRLock)
    # default-v1 doesn't include PolicyAuthorizeNV (command 0x12A = 298)
    # The 'custom' profile allows enabling additional commands
    # Remove --not-overwrite to ensure fresh state with correct profile
    if command -v swtpm_setup &>/dev/null; then
        # Try custom profile first - this allows adding commands
        swtpm_setup --tpmstate "${TPM_DIR}" --tpm2 --createek --profile-name custom 2>&1 && return 0
        # Fall back to default if custom fails
        warn "Custom profile failed, trying default..."
        swtpm_setup --tpmstate "${TPM_DIR}" --tpm2 --createek
    fi
}

start_swtpm() {
    command -v swtpm &>/dev/null || error "swtpm not found."

    # Kill any existing instance and clean up sockets
    pkill -f "swtpm socket.*${TPM_SOCKET}" 2>/dev/null || true
    sleep 0.3
    rm -f "${TPM_SOCKET}" "${TPM_SOCKET}.ctrl" 2>/dev/null || true

    info "Starting swtpm..."
    # Use startup-none to preserve NV indexes (PCRLock requirement)
    # The NV index created during enrollment must persist for unlock
    swtpm socket \
        --tpmstate dir="${TPM_DIR}" \
        --ctrl type=unixio,path="${TPM_SOCKET}" \
        --tpm2 \
        --flags startup-none,not-need-init \
        --log level=5 >> "${TPM_DIR}/swtpm.log" 2>&1 &

    sleep 1
    [ -S "${TPM_SOCKET}" ] || { tail -20 "${TPM_DIR}/swtpm.log"; error "Failed to start swtpm"; }
    info "swtpm started at ${TPM_SOCKET}"
}

start_swtpm_for_enrollment() {
    info "Starting swtpm for enrollment..."
    rm -f "${TPM_SOCKET}" "${TPM_SOCKET}.ctrl" 2>/dev/null || true
    
    # Check if TPM state exists with NV indexes or persistent state
    # Only check for NVChip - tpm2-00.permall exists even in fresh TPM (for EK)
    if [ -f "${TPM_DIR}/NVChip" ]; then
        info "Using existing TPM state with NV indexes..."
    else
        info "No TPM state found, initializing..."
        init_swtpm_state
    fi
    
    # Use startup-clear to ensure clean TPM state during enrollment
    # After enrollment, we'll preserve the state for unlock tests
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
    info "Using TPM_SOCKET: ${TPM_SOCKET}"
    info "Testing swtpm connection..."
    
    # Test swtpm is accessible
    if [ -S "${TPM_SOCKET}" ]; then
        info "swtpm socket exists: ${TPM_SOCKET}"
    else
        warn "swtpm socket NOT found: ${TPM_SOCKET}"
    fi
    
    info "Running systemd-pcrlock with SYSTEMD_TPM2_DEVICE=swtpm:path=${TPM_SOCKET}..."
    
    # Capture both stdout and stderr
    local output
    local exit_code
    # Use --pcr=23 to simplify testing - only lock to PCR 23
    output=$(sudo SYSTEMD_TPM2_DEVICE="swtpm:path=${TPM_SOCKET}" \
        "${pcrlock_bin}" make-policy --policy="${TEST_DIR}/pcrlock.json" --pcr=23 --force 2>&1) 
    exit_code=$?
    
    info "systemd-pcrlock output:"
    info "${output}"
    
    if [ $exit_code -eq 0 ]; then
        sudo chown "$(id -u):$(id -g)" "${TEST_DIR}/pcrlock.json"
        info "pcrlock policy created successfully"
        copy_pcrlock_to_boot
    else
        warn "pcrlock generation failed with exit code: ${exit_code}"
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

# Export TPM token from the test disk for debugging
export_token() {
    [ -f "${DISK_IMG}" ] || error "Disk not found. Run: $0 disk"
    local tmpraw
    tmpraw=$(mktemp)
    qemu-img convert -f qcow2 -O raw "${DISK_IMG}" "${tmpraw}"
    local loop
    loop=$(sudo losetup -f --show "${tmpraw}")
    sudo partprobe "${loop}"; sleep 1
    local luks_part="${loop}p2"
    echo "Unlocking LUKS device..."
    echo "${LUKS_PASS}" | sudo cryptsetup open "${luks_part}" testluks -
    echo ""
    echo "=== TPM Token Export ==="
    sudo cryptsetup token export /dev/mapper/testluks --token-id 0 2>/dev/null || \
        sudo cryptsetup token export "${luks_part}" --token-id 0 2>/dev/null || \
        echo "No token found or export failed"
    echo ""
    sudo cryptsetup close testluks 2>/dev/null || true
    sudo losetup -d "${loop}"
    rm -f "${tmpraw}"
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

    # Generate pcrlock policy on swtpm (this creates the NV index in swtpm!)
    generate_pcrlock

    info "Enrolling TPM2 token (no PIN)..."
    sudo "${SCRIPT_DIR}/helpers/enroll-tpm.sh" "${DISK_IMG}" "${DISK_RAW}" "${TPM_SOCKET}" "${LUKS_PASS}" "${TEST_DIR}/pcrlock.json" ""

    stop_swtpm
    info "TPM enrollment complete (no PIN)"
}

enroll_tpm_pin() {
    check_swtpm_deps
    init_swtpm_state
    start_swtpm_for_enrollment

    # Generate pcrlock policy on swtpm (this creates the NV index in swtpm!)
    generate_pcrlock

    info "Enrolling TPM2 token with PIN: ${TPM_PIN}..."
    sudo "${SCRIPT_DIR}/helpers/enroll-tpm.sh" "${DISK_IMG}" "${DISK_RAW}" "${TPM_SOCKET}" "${LUKS_PASS}" "${TEST_DIR}/pcrlock.json" "${TPM_PIN}"

    stop_swtpm
    info "TPM enrollment complete with PIN"
}

enroll_tpm_pin_pcr() {
    check_swtpm_deps
    
    # For PCRLock we need fresh TPM state with PolicyAuthorizeNV support
    # Always reinitialize to ensure correct profile is applied
    info "Initializing fresh TPM state for PCRLock..."
    init_swtpm_state
    
    # Check if disk already has TPM token - if so, skip enrollment
    if [ -f "${DISK_IMG}" ]; then
        info "Checking if disk already has TPM token..."
        local tmpraw=$(mktemp)
        qemu-img convert -f qcow2 -O raw "${DISK_IMG}" "${tmpraw}"
        local loop=$(sudo losetup -f --show "${tmpraw}")
        sudo partprobe "$loop" 2>/dev/null || true
        sleep 1
        local PART="${loop}p2"; [ -e "$PART" ] || PART="${loop}p1"
        
        # Check if token exists using cryptsetup
        if sudo cryptsetup luksDump "${PART}" 2>/dev/null | grep -q "systemd-tpm2"; then
            info "Disk already has TPM token, skipping enrollment..."
            sudo losetup -d "$loop" 2>/dev/null || true
            rm -f "${tmpraw}"
            return 0
        fi
        sudo losetup -d "$loop" 2>/dev/null || true
        rm -f "${tmpraw}"
    fi
    
    start_swtpm_for_enrollment

    # Generate pcrlock policy on swtpm (this creates the NV index in swtpm!)
    generate_pcrlock

    info "Enrolling TPM2 token with PIN + PCR23: ${TPM_PIN}..."

    # Convert disk for enrollment
    local tmpraw=$(mktemp)
    qemu-img convert -f qcow2 -O raw "${DISK_IMG}" "${tmpraw}"
    local loop=$(sudo losetup -f --show "${tmpraw}")
    sudo partprobe "$loop"; sleep 1
    local PART="${loop}p2"; [ -e "$PART" ] || PART="${loop}p1"

    local PASSFILE=$(mktemp)
    echo -n "${LUKS_PASS}" > "$PASSFILE"

    # Enroll with PIN + PCRLock (pcrlock handles PCR policy internally)
    # Note: --tpm2-pcrs should NOT be used with --tpm2-pcrlock
    sudo systemd-cryptenroll \
        --tpm2-device="swtpm:path=${TPM_SOCKET}" \
        --tpm2-with-pin=yes \
        --wipe-slot=tpm2 \
        --unlock-key-file="$PASSFILE" \
        --tpm2-pcrlock="${TEST_DIR}/pcrlock.json" \
        "$PART"

    rm -f "$PASSFILE"
    sudo losetup -d "$loop"
    qemu-img convert -f raw -O qcow2 "${tmpraw}" "${DISK_IMG}"
    rm -f "${tmpraw}"

    stop_swtpm
    info "TPM enrollment complete with PIN + PCR23"
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
    
    # Handle console resizing if requested
    local old_stty=""
    if [ -n "${CONSOLE_SIZE}" ]; then
        old_stty=$(stty -g)
        # Split rows/cols
        local rows=$(echo "${CONSOLE_SIZE}" | awk '{print $1}')
        local cols=$(echo "${CONSOLE_SIZE}" | awk '{print $2}')
        if [ -n "$rows" ] && [ -n "$cols" ]; then
            info "Resizing console to ${rows}x${cols}..."
            stty rows "$rows" cols "$cols"
        fi
    fi

    qemu-system-x86_64 -m 2G -cpu host -enable-kvm \
        -kernel "${kernel}" -initrd "${INITRAMFS}" \
        -append "root=/dev/vg0/root console=ttyS0" \
        -device virtio-scsi-pci,id=scsi0 \
        -device scsi-hd,drive=hd0,bus=scsi0.0 \
        -drive file="${DISK_IMG}",format=qcow2,id=hd0,if=none \
        -nographic -no-reboot
    
    # Restore console size if we changed it
    if [ -n "${old_stty}" ]; then
        stty "${old_stty}"
        info "Console size restored"
    fi
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

    # Handle console resizing if requested
    local old_stty=""
    if [ -n "${CONSOLE_SIZE}" ]; then
        old_stty=$(stty -g)
        local rows=$(echo "${CONSOLE_SIZE}" | awk '{print $1}')
        local cols=$(echo "${CONSOLE_SIZE}" | awk '{print $2}')
        if [ -n "$rows" ] && [ -n "$cols" ]; then
            info "Resizing console to ${rows}x${cols}..."
            stty rows "$rows" cols "$cols"
        fi
    fi

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

    if [ -n "${old_stty}" ]; then
        stty "${old_stty}"
    fi

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
    enroll-tpm-pin)
        enroll_tpm_pin ;;
    all-tpm)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs; run_qemu_tpm "${2:-}" ;;
    all-tpm-tui)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs_tui; run_qemu_tpm "${2:-}" ;;
    all-tpm-pin)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm_pin
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs; run_qemu_tpm "${2:-}" ;;
    all-tpm-pin-tui)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm_pin
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs_tui; run_qemu_tpm "${2:-}" ;;
    enroll-tpm-pin-pcr)
        check_deps; setup_test_dir; enroll_tpm_pin_pcr ;;
    all-tpm-pin-pcr)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm_pin_pcr
        build_initramfs; run_qemu_tpm "${2:-}" ;;
    all-tpm-pin-pcr-tui)
        check_deps; setup_test_dir; create_test_disk; enroll_tpm_pin_pcr
        build_initramfs_tui; run_qemu_tpm "${2:-}" ;;
    export-token)
        export_token ;;
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
  tpm-tui [kernel]  Run QEMU with swtpm (TUI mode, use build-tui first)
  enroll-tpm         Enroll TPM2 token (no PIN, no PCRs)
  enroll-tpm-pin     Enroll TPM2 token with PIN (no PCRs)
  enroll-tpm-pin-pcr Enroll TPM2 token with PIN + PCR23
  all-tpm [kernel]   Full TPM test: disk, enroll, build, run (debug mode)
  all-tpm-tui [kernel] Full TPM test with TUI mode
  all-tpm-pin [kernel] Full TPM test with PIN (debug mode)
  all-tpm-pin-tui [kernel] Full TPM test with PIN and TUI mode
  all-tpm-pin-pcr [kernel] Full TPM test with PIN + PCR23 (debug mode)
  all-tpm-pin-pcr-tui [kernel] Full TPM test with PIN + PCR23 and TUI mode

Debug Commands:
  export-token       Export TPM token from test disk and sleep 2s for capture

Maintenance:
  clean              Remove all test files

Examples:
  $0 build
  $0 build-tui
  $0 all-tpm
  $0 all-tpm-pin-tui   # Test PIN entry in TUI mode
  $0 run /boot/vmlinuz
HELP
        exit 1
        ;;
esac
