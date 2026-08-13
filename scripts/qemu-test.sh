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

# OVMF / Secure Boot test paths
KEY_DIR="${TEST_DIR}/keys"
OVMF_DIR="${TEST_DIR}/ovmf"
OVMF_CODE_SECBOOT="/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd"
OVMF_VARS_SECBOOT_TEMPLATE="/usr/share/edk2/OvmfX64/OVMF_VARS.secboot.fd"
OVMF_CODE_NONSECURE="/usr/share/edk2/OvmfX64/OVMF_CODE.fd"
OVMF_VARS_NONSECURE_TEMPLATE="/usr/share/edk2/OvmfX64/OVMF_VARS.fd"
PROVISION_INITRAMFS="${OVMF_DIR}/provision-initramfs.img"
PROVISION_KERNEL="${OVMF_DIR}/provision-vmlinuz"
TEST_UKI="${TEST_DIR}/test-uki.efi"
ESP_IMG="${TEST_DIR}/esp.img"

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
    # Check for pre-compiled test kernel
    if [ -f "${PROJECT_DIR}/testdata/kernel/bzImage" ]; then
        realpath "${PROJECT_DIR}/testdata/kernel/bzImage"
        return
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
# OVMF / Secure Boot Functions
#=============================================================================

check_ovmf_deps() {
    for cmd in openssl cert-to-efi-sig-list sign-efi-sig-list efi-updatevar sbsign ukify objcopy; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    [ -f "$OVMF_CODE_SECBOOT" ] || error "OVMF Secure Boot CODE not found: $OVMF_CODE_SECBOOT"
    [ -f "$OVMF_VARS_SECBOOT_TEMPLATE" ] || error "OVMF Secure Boot VARS template not found: $OVMF_VARS_SECBOOT_TEMPLATE"
}

generate_secureboot_keys() {
    info "Generating Secure Boot test keys..."
    mkdir -p "$KEY_DIR"

    # PK (Platform Key - root of trust)
    openssl req -new -x509 -newkey rsa:2048 -keyout "${KEY_DIR}/PK.key" \
        -out "${KEY_DIR}/PK.crt" -days 3650 -nodes \
        -subj "/CN=Vanguard Test PK" 2>/dev/null

    # KEK (Key Exchange Key)
    openssl req -new -x509 -newkey rsa:2048 -keyout "${KEY_DIR}/KEK.key" \
        -out "${KEY_DIR}/KEK.crt" -days 3650 -nodes \
        -subj "/CN=Vanguard Test KEK" 2>/dev/null

    # db (signature database)
    openssl req -new -x509 -newkey rsa:2048 -keyout "${KEY_DIR}/db.key" \
        -out "${KEY_DIR}/db.crt" -days 3650 -nodes \
        -subj "/CN=Vanguard Test db" 2>/dev/null

    # Create ESL files
    local EFI_GLOBAL_GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"
    local EFI_DB_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"

    cert-to-efi-sig-list -g "$EFI_GLOBAL_GUID" "${KEY_DIR}/PK.crt" "${KEY_DIR}/PK.esl"
    cert-to-efi-sig-list -g "$EFI_GLOBAL_GUID" "${KEY_DIR}/KEK.crt" "${KEY_DIR}/KEK.esl"
    cert-to-efi-sig-list -g "$EFI_DB_GUID" "${KEY_DIR}/db.crt" "${KEY_DIR}/db.esl"

    # Create signed auth files
    sign-efi-sig-list -k "${KEY_DIR}/PK.key" -c "${KEY_DIR}/PK.crt" \
        PK "${KEY_DIR}/PK.esl" "${KEY_DIR}/PK.auth" 2>/dev/null
    sign-efi-sig-list -k "${KEY_DIR}/PK.key" -c "${KEY_DIR}/PK.crt" \
        KEK "${KEY_DIR}/KEK.esl" "${KEY_DIR}/KEK.auth" 2>/dev/null
    sign-efi-sig-list -k "${KEY_DIR}/KEK.key" -c "${KEY_DIR}/KEK.crt" \
        db "${KEY_DIR}/db.esl" "${KEY_DIR}/db.auth" 2>/dev/null

    info "Keys generated: ${KEY_DIR}/"
}

build_provision_initramfs() {
    info "Building OVMF provisioning initramfs..."
    mkdir -p "$OVMF_DIR"

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir"/{bin,dev,proc,sys,etc/keys,var,run,tmp}

    # Busybox
    local BB=$(which busybox)
    cp "$BB" "$tmpdir/bin/busybox"
    for cmd in sh mount umount ls cat echo sleep poweroff mkdir cp od; do
        ln -sf busybox "$tmpdir/bin/$cmd"
    done

    # efi-updatevar
    local EFI_UPDATEVAR=$(which efi-updatevar)
    cp "$EFI_UPDATEVAR" "$tmpdir/bin/efi-updatevar"
    ldd "$EFI_UPDATEVAR" 2>/dev/null | grep -o '/[^ ]*' | while read lib; do
        mkdir -p "$tmpdir$(dirname "$lib")"
        cp "$lib" "$tmpdir$lib" 2>/dev/null || true
    done

    # Copy auth files
    cp "${KEY_DIR}/PK.auth" "${KEY_DIR}/KEK.auth" "${KEY_DIR}/db.auth" "$tmpdir/etc/keys/"

    # Init script
    cat > "$tmpdir/init" << 'PROVISION_INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null

echo "=== OVMF Secure Boot Key Provisioning ==="
[ -d /sys/firmware/efi/efivars ] || { echo "ERROR: efivarfs not available"; poweroff -f; }

# Check Setup Mode
SM="/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
[ -f "$SM" ] && echo "Setup Mode: $(od -A n -t u1 -j 4 "$SM" 2>/dev/null | tr -d ' ')"

echo "Enrolling keys..."
efi-updatevar -f /etc/keys/db.auth db 2>&1 && echo "db: OK"
efi-updatevar -f /etc/keys/KEK.auth KEK 2>&1 && echo "KEK: OK"
efi-updatevar -f /etc/keys/PK.auth PK 2>&1 && echo "PK: OK (locked)"

# Verify
SB="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
[ -f "$SB" ] && echo "Secure Boot: $(od -A n -t u1 -j 4 "$SB" 2>/dev/null | tr -d ' ')"

sleep 2
echo "Powering off..."
poweroff -f
PROVISION_INIT
    chmod +x "$tmpdir/init"

    cd "$tmpdir"
    find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$PROVISION_INITRAMFS"
    cd - > /dev/null
    rm -rf "$tmpdir"
    info "Provisioning initramfs: ${PROVISION_INITRAMFS}"
}

find_helper_kernel() {
    info "Finding kernel for helper VM..."
    if [ -f /boot/EFI/Gentoo/kernel.efi ]; then
        cp /boot/EFI/Gentoo/kernel.efi /tmp/extract-uki.efi 2>/dev/null
        if objcopy --dump-section .linux="$PROVISION_KERNEL" /tmp/extract-uki.efi 2>/dev/null; then
            rm -f /tmp/extract-uki.efi
            info "Kernel extracted from UKI: $PROVISION_KERNEL"
            return 0
        fi
        rm -f /tmp/extract-uki.efi
    fi
    for k in /boot/vmlinuz-* /boot/vmlinuz; do
        [ -f "$k" ] && { cp "$k" "$PROVISION_KERNEL"; info "Using kernel: $k"; return 0; }
    done
    error "No kernel found"
}

provision_ovmf() {
    check_ovmf_deps
    generate_secureboot_keys
    build_provision_initramfs
    find_helper_kernel

    info "Booting helper VM to provision OVMF..."
    cp "$OVMF_VARS_SECBOOT_TEMPLATE" "${OVMF_DIR}/OVMF_VARS.secboot.fd"

    pkill -f "swtpm socket.*${TPM_SOCKET}" 2>/dev/null || true
    rm -f "$TPM_SOCKET" "${TPM_SOCKET}.ctrl"
    rm -rf "$TPM_DIR"; mkdir -p "$TPM_DIR"

    swtpm socket \
        --tpmstate dir="$TPM_DIR" \
        --ctrl type=unixio,path="$TPM_SOCKET" \
        --tpm2 \
        --flags startup-clear,not-need-init \
        --log level=1,file="${TPM_DIR}/swtpm.log" &

    local swtpm_pid=$!
    sleep 1
    [ -S "$TPM_SOCKET" ] || error "swtpm failed"

    timeout 30 qemu-system-x86_64 \
        -machine q35,smm=on \
        -m 256M \
        -nographic -no-reboot \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE_SECBOOT" \
        -drive if=pflash,format=raw,file="${OVMF_DIR}/OVMF_VARS.secboot.fd" \
        -kernel "$PROVISION_KERNEL" \
        -initrd "$PROVISION_INITRAMFS" \
        -append "console=ttyS0" \
        -chardev socket,id=chrtpm,path="$TPM_SOCKET" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-crb,tpmdev=tpm0 \
        -serial mon:stdio 2>&1 | tail -20

    kill "$swtpm_pid" 2>/dev/null || true
    wait "$swtpm_pid" 2>/dev/null || true

    info "OVMF provisioned: ${OVMF_DIR}/OVMF_VARS.secboot.fd"
    info "Signing keys: ${KEY_DIR}/"
}

build_test_uki() {
    [ -f "$INITRAMFS" ] || error "Initramfs not found. Run: $0 build"
    [ -f "$PROVISION_KERNEL" ] || find_helper_kernel
    [ -f "${KEY_DIR}/db.key" ] || error "Keys not found. Run: $0 provision-ovmf"

    info "Building test UKI..."
    local os_release="/usr/lib/os-release"
    [ -f "$os_release" ] || os_release="/etc/os-release"

    ukify build \
        --linux "$PROVISION_KERNEL" \
        --initrd "$INITRAMFS" \
        --cmdline "root=/dev/vg0/root console=ttyS0" \
        --os-release "$os_release" \
        --signtool sbsign \
        --signing-key "${KEY_DIR}/db.key" \
        --secureboot-certificate "${KEY_DIR}/db.crt" \
        -o "$TEST_UKI" 2>&1

    [ -f "$TEST_UKI" ] || error "UKI build failed"
    info "Test UKI: ${TEST_UKI} ($(du -h "$TEST_UKI" | cut -f1))"
}

create_esp_image() {
    [ -f "$TEST_UKI" ] || error "Test UKI not found. Run: $0 build-uki"

    info "Creating ESP image with test UKI..."
    # Create 200MB FAT32 ESP image
    dd if=/dev/zero of="$ESP_IMG" bs=1M count=200 2>/dev/null
    mkfs.vfat -F 32 "$ESP_IMG" 2>/dev/null

    # Create directory structure and copy UKI
    mmd -i "$ESP_IMG" ::/EFI
    mmd -i "$ESP_IMG" ::/EFI/BOOT
    mmd -i "$ESP_IMG" ::/EFI/GENTOO
    mcopy -i "$ESP_IMG" "$TEST_UKI" ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$ESP_IMG" "$TEST_UKI" ::/EFI/GENTOO/kernel.efi

    info "ESP image: ${ESP_IMG} ($(du -h "$ESP_IMG" | cut -f1))"
}

run_qemu_uefi() {
    [ -f "$INITRAMFS" ] || error "Initramfs not found. Run: $0 build"
    [ -f "$ESP_IMG" ] || error "ESP not found. Run: $0 build-uki"

    cp "$OVMF_VARS_NONSECURE_TEMPLATE" "${OVMF_DIR}/OVMF_VARS.fd"

    start_swtpm
    trap stop_swtpm EXIT

    info "Starting QEMU with OVMF (non-secure) + TPM..."
    timeout 60 qemu-system-x86_64 \
        -machine q35,smm=on \
        -m 2G -cpu host -enable-kvm \
        -nographic -no-reboot \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE_NONSECURE" \
        -drive if=pflash,format=raw,file="${OVMF_DIR}/OVMF_VARS.fd" \
        -drive id=esp,format=raw,if=none,file="$ESP_IMG" \
        -device ich9-ahci,id=ahci \
        -device ide-hd,drive=esp,bus=ahci.0 \
        -chardev socket,id=chrtpm,path="$TPM_SOCKET" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-crb,tpmdev=tpm0 \
        -serial mon:stdio
}

run_qemu_secure() {
    [ -f "$INITRAMFS" ] || error "Initramfs not found. Run: $0 build"
    [ -f "$ESP_IMG" ] || error "ESP not found. Run: $0 build-uki"
    [ -f "${OVMF_DIR}/OVMF_VARS.secboot.fd" ] || error "OVMF not provisioned. Run: $0 provision-ovmf"

    start_swtpm
    trap stop_swtpm EXIT

    info "Starting QEMU with OVMF Secure Boot + TPM..."
    timeout 60 qemu-system-x86_64 \
        -machine q35,smm=on \
        -m 2G -cpu host -enable-kvm \
        -nographic -no-reboot \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE_SECBOOT" \
        -drive if=pflash,format=raw,file="${OVMF_DIR}/OVMF_VARS.secboot.fd" \
        -drive id=esp,format=raw,if=none,file="$ESP_IMG" \
        -device ich9-ahci,id=ahci \
        -device ide-hd,drive=esp,bus=ahci.0 \
        -chardev socket,id=chrtpm,path="$TPM_SOCKET" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-crb,tpmdev=tpm0 \
        -serial mon:stdio
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
    provision-ovmf)
        check_ovmf_deps; provision_ovmf ;;
    build-uki)
        build_test_uki; create_esp_image ;;
    run-uefi)
        run_qemu_uefi ;;
    run-secure)
        run_qemu_secure ;;
    all-uefi)
        check_deps; check_ovmf_deps; setup_test_dir
        create_test_disk; enroll_tpm
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs; build_test_uki; create_esp_image
        run_qemu_uefi ;;
    all-secure)
        check_deps; check_ovmf_deps; setup_test_dir
        provision_ovmf
        create_test_disk; enroll_tpm
        start_swtpm_for_enrollment; generate_pcrlock; stop_swtpm
        build_initramfs; build_test_uki; create_esp_image
        run_qemu_secure ;;
    cover)
        # Coverage test: build init with -cover, run QEMU, collect coverage
        check_deps; setup_test_dir
        info "Building vanguard CLI..."
        go build -o vanguard ./cmd/vanguard/
        info "Building covered init binary..."
        CGO_ENABLED=0 go build -cover -tags debug -o "${TEST_DIR}/init-cover" ./init/
        info "Covered init binary built (${TEST_DIR}/init-cover)"

        # Create cover disk (small FAT image for .cov files)
        info "Creating cover disk..."
        dd if=/dev/zero of="${TEST_DIR}/cover.img" bs=1M count=10 2>/dev/null
        mkfs.vfat -F 32 "${TEST_DIR}/cover.img" 2>/dev/null

        # Generate initramfs with covered init binary
        info "Generating initramfs with covered init..."
        ./vanguard generate -o "${INITRAMFS}" --debug --init-binary "${TEST_DIR}/init-cover"
        replace_initramfs_fstab

        # Set up test disk if needed
        [ ! -f "${DISK_IMG}" ] && create_test_disk

        # Find kernel
        kernel=$(find_kernel "${2:-}") || error "Kernel not found"

        # Start swtpm
        start_swtpm
        trap stop_swtpm EXIT

        info "Starting QEMU for coverage collection..."
        timeout 120 qemu-system-x86_64 \
            -m 2G -cpu host -enable-kvm \
            -kernel "${kernel}" -initrd "${INITRAMFS}" \
            -append "root=/dev/vg0/root console=ttyS0 vanguard.testmode=1" \
            -device virtio-scsi-pci,id=scsi0 \
            -device scsi-hd,drive=hd0,bus=scsi0.0 \
            -drive file="${DISK_IMG}",format=qcow2,id=hd0,if=none \
            -drive id=cover,format=raw,if=none,file="${TEST_DIR}/cover.img" \
            -device virtio-blk-pci,drive=cover \
            -chardev socket,id=chrtpm,path="${TPM_SOCKET}" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-crb,tpmdev=tpm0 \
            -nographic -no-reboot 2>&1 | tee "${TEST_DIR}/cover-boot.log"

        # Extract coverage data from cover disk
        info "Extracting coverage data..."
        mkdir -p "${TEST_DIR}/cover-data"
        mcopy -s -i "${TEST_DIR}/cover.img" ::/ "${TEST_DIR}/cover-data/" 2>/dev/null || true

        # Check if coverage data was collected
        cover_files=$(find "${TEST_DIR}/cover-data" -name "*.cov" 2>/dev/null | wc -l)
        if [ "$cover_files" -eq 0 ]; then
            warn "No .cov files found. Coverage collection may have failed."
            warn "Check boot log: ${TEST_DIR}/cover-boot.log"
        else
            info "Collected ${cover_files} coverage files"

            # Convert QEMU coverage to text format
            go tool covdata textfmt -i "${TEST_DIR}/cover-data" -o "${TEST_DIR}/qemu-cover.out" 2>/dev/null
            if [ -f "${TEST_DIR}/qemu-cover.out" ]; then
                info "QEMU coverage:"
                go tool cover -func="${TEST_DIR}/qemu-cover.out" 2>&1 | tail -1
            fi
        fi

        # Run go test coverage
        info "Running go test coverage..."
        go test -coverprofile="${TEST_DIR}/gotest.out" ./... 2>&1 | tail -5
        if [ -f "${TEST_DIR}/gotest.out" ]; then
            info "Go test coverage:"
            go tool cover -func="${TEST_DIR}/gotest.out" 2>&1 | tail -1
        fi

        # Report combined estimate
        info "=== Combined Coverage Estimate ==="
        if [ -f "${TEST_DIR}/qemu-cover.out" ] && [ -f "${TEST_DIR}/gotest.out" ]; then
            # Merge coverage profiles
            # Go 1.20+ covdata merge can combine .cov directories
            # But we have text .out files, not .cov directories
            # So we report both separately
            echo ""
            echo "QEMU boot coverage:"
            go tool cover -func="${TEST_DIR}/qemu-cover.out" 2>&1 | tail -1
            echo ""
            echo "Go test coverage:"
            go tool cover -func="${TEST_DIR}/gotest.out" 2>&1 | tail -1
            echo ""
            echo "Note: These are separate measurements. QEMU covers init/* code,"
            echo "go test covers internal/* and cmd/* code."
        elif [ -f "${TEST_DIR}/qemu-cover.out" ]; then
            go tool cover -func="${TEST_DIR}/qemu-cover.out" 2>&1 | tail -1
        elif [ -f "${TEST_DIR}/gotest.out" ]; then
            go tool cover -func="${TEST_DIR}/gotest.out" 2>&1 | tail -1
        else
            warn "No coverage data collected"
        fi
        ;;
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

UEFI / Secure Boot Commands:
  provision-ovmf      Generate Secure Boot keys + provision OVMF NVRAM
  build-uki           Build signed test UKI with ukify + sbsign
  run-uefi            Boot QEMU with OVMF (non-secure) + swtpm + ESP
  run-secure          Boot QEMU with OVMF Secure Boot + swtpm + signed UKI
  all-uefi            Full UEFI test: disk, enroll, build, run-uefi
  all-secure          Full Secure Boot test: provision, disk, enroll, build, run-secure

Maintenance:
  clean              Remove all test files

Examples:
  $0 build
  $0 build-tui
  $0 all-tpm
  $0 all-tpm-pin-tui   # Test PIN entry in TUI mode
  $0 run /boot/vmlinuz
  $0 provision-ovmf    # Provision OVMF with Secure Boot keys
  $0 all-secure        # Full Secure Boot + TPM test
  $0 cover [kernel]    # Coverage test: build -cover init, run QEMU, collect coverage
HELP
        exit 1
        ;;
esac
