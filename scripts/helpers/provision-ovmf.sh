#!/bin/bash
# Helper script for generating Secure Boot keys and provisioning OVMF NVRAM.
# This script:
# 1. Generates self-signed PK/KEK/db key pairs with openssl
# 2. Creates EFI Signature List (.esl) files with cert-to-efi-sig-list
# 3. Creates signed .auth files with sign-efi-sig-list
# 4. Builds a minimal initramfs that enrolls the keys into OVMF via efivarfs
# 5. Boots a helper VM with OVMF secboot to provision the keys
#
# Usage: provision-ovmf.sh <test-dir> <ovmf-code> <ovmf-vars-template>
# Output: <test-dir>/ovmf/OVMF_VARS.secboot.fd (provisioned with keys)
#         <test-dir>/keys/ (PK/KEK/db key pairs for signing)

set -e

TEST_DIR="$1"
OVMF_CODE="$2"
OVMF_VARS_TEMPLATE="$3"

KEY_DIR="${TEST_DIR}/keys"
OVMF_DIR="${TEST_DIR}/ovmf"
PROVISION_INITRAMFS="${OVMF_DIR}/provision-initramfs.img"
PROVISION_KERNEL="${OVMF_DIR}/provision-vmlinuz"
TPM_SOCKET="${OVMF_DIR}/swtpm.sock"
TPM_DIR="${OVMF_DIR}/tpm"

# EFI variable GUIDs
EFI_GLOBAL_GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_IMAGE_SECURITY_DATABASE_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check dependencies
for cmd in openssl cert-to-efi-sig-list sign-efi-sig-list efi-updatevar sbsign; do
    command -v "$cmd" &>/dev/null || error "Missing dependency: $cmd (install efitools, sbsigntool)"
done

[ -f "$OVMF_CODE" ] || error "OVMF CODE firmware not found: $OVMF_CODE"
[ -f "$OVMF_VARS_TEMPLATE" ] || error "OVMF VARS template not found: $OVMF_VARS_TEMPLATE"

mkdir -p "$KEY_DIR" "$OVMF_DIR" "$TPM_DIR"

#=============================================================================
# Step 1: Generate self-signed PK/KEK/db key pairs
#=============================================================================
generate_keys() {
    info "Generating Secure Boot keys..."

    # PK (Platform Key - root of trust)
    openssl req -new -x509 -newkey rsa:2048 -keyout "${KEY_DIR}/PK.key" \
        -out "${KEY_DIR}/PK.crt" -days 3650 -nodes \
        -subj "/CN=Vanguard Test PK" 2>/dev/null

    # KEK (Key Exchange Key - can update db/dbx)
    openssl req -new -x509 -newkey rsa:2048 -keyout "${KEY_DIR}/KEK.key" \
        -out "${KEY_DIR}/KEK.crt" -days 3650 -nodes \
        -subj "/CN=Vanguard Test KEK" 2>/dev/null

    # db (signature database - allowed bootloaders)
    openssl req -new -x509 -newkey rsa:2048 -keyout "${KEY_DIR}/db.key" \
        -out "${KEY_DIR}/db.crt" -days 3650 -nodes \
        -subj "/CN=Vanguard Test db" 2>/dev/null

    info "Keys generated in ${KEY_DIR}/"
}

#=============================================================================
# Step 2: Create EFI Signature Lists and signed auth files
#=============================================================================
create_esl_files() {
    info "Creating EFI Signature Lists..."

    # Convert certs to ESL (EFI Signature List)
    cert-to-efi-sig-list -g "$EFI_GLOBAL_GUID" "${KEY_DIR}/PK.crt" "${KEY_DIR}/PK.esl"
    cert-to-efi-sig-list -g "$EFI_GLOBAL_GUID" "${KEY_DIR}/KEK.crt" "${KEY_DIR}/KEK.esl"
    cert-to-efi-sig-list -g "$EFI_IMAGE_SECURITY_DATABASE_GUID" "${KEY_DIR}/db.crt" "${KEY_DIR}/db.esl"

    # Create signed .auth files (for User Mode enrollment)
    # PK auth is signed by PK itself (self-signed for the first enrollment)
    sign-efi-sig-list -k "${KEY_DIR}/PK.key" -c "${KEY_DIR}/PK.crt" \
        PK "${KEY_DIR}/PK.esl" "${KEY_DIR}/PK.auth" 2>/dev/null

    # KEK auth is signed by PK
    sign-efi-sig-list -k "${KEY_DIR}/PK.key" -c "${KEY_DIR}/PK.crt" \
        KEK "${KEY_DIR}/KEK.esl" "${KEY_DIR}/KEK.auth" 2>/dev/null

    # db auth is signed by KEK
    sign-efi-sig-list -k "${KEY_DIR}/KEK.key" -c "${KEY_DIR}/KEK.crt" \
        db "${KEY_DIR}/db.esl" "${KEY_DIR}/db.auth" 2>/dev/null

    info "ESL and auth files created"
}

#=============================================================================
# Step 3: Build a minimal initramfs for key provisioning
#=============================================================================
build_provision_initramfs() {
    info "Building minimal provisioning initramfs..."

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir"/{bin,dev,proc,sys,etc,var,run,tmp}

    # Use busybox as the init
    BB=$(which busybox)
    cp "$BB" "$tmpdir/bin/busybox"
    for cmd in sh mount umount ls cat echo sleep poweroff mkdir cp; do
        ln -sf busybox "$tmpdir/bin/$cmd"
    done

    # Copy efi-updatevar and its dependencies
    EFI_UPDATEVAR=$(which efi-updatevar)
    cp "$EFI_UPDATEVAR" "$tmpdir/bin/efi-updatevar"
    # Copy required shared libraries
    ldd "$EFI_UPDATEVAR" 2>/dev/null | grep -o '/[^ ]*' | while read lib; do
        mkdir -p "$tmpdir$(dirname "$lib")"
        cp "$lib" "$tmpdir$lib" 2>/dev/null || true
    done

    # Copy the auth files into the initramfs
    mkdir -p "$tmpdir/etc/keys"
    cp "${KEY_DIR}/PK.auth" "$tmpdir/etc/keys/PK.auth"
    cp "${KEY_DIR}/KEK.auth" "$tmpdir/etc/keys/KEK.auth"
    cp "${KEY_DIR}/db.auth" "$tmpdir/etc/keys/db.auth"

    # Create the init script
    cat > "$tmpdir/init" << 'INIT'
#!/bin/sh
# Provisioning init - enrolls Secure Boot keys into OVMF via efivarfs

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null

echo "=== OVMF Secure Boot Key Provisioning ==="
echo ""

# Check if efivarfs is mounted
if [ ! -d /sys/firmware/efi/efivars ]; then
    echo "ERROR: efivarfs not available"
    poweroff -f
fi

# Check current Secure Boot state
SB_VAR="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [ -f "$SB_VAR" ]; then
    SB_VAL=$(od -A n -t u1 -j 4 "$SB_VAR" 2>/dev/null | tr -d ' ')
    if [ "$SB_VAL" = "1" ]; then
        echo "Secure Boot is ENABLED"
    else
        echo "Secure Boot is DISABLED (Setup Mode)"
    fi
fi

SM_VAR="/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [ -f "$SM_VAR" ]; then
    SM_VAL=$(od -A n -t u1 -j 4 "$SM_VAR" 2>/dev/null | tr -d ' ')
    if [ "$SM_VAL" = "1" ]; then
        echo "Setup Mode is ON (can enroll unsigned)"
    else
        echo "Setup Mode is OFF (User Mode - need signed auth)"
    fi
fi

echo ""
echo "Enrolling keys..."

# In Setup Mode, we can use -e (unsigned ESL) which is simpler
# But .auth files work in both modes
efi-updatevar -f /etc/keys/db.auth db 2>&1
echo "db: $?"

efi-updatevar -f /etc/keys/KEK.auth KEK 2>&1
echo "KEK: $?"

# PK enrollment locks the platform (transitions to User Mode)
efi-updatevar -f /etc/keys/PK.auth PK 2>&1
echo "PK: $?"

echo ""
echo "=== Provisioning complete ==="

# Verify
if [ -f "$SB_VAR" ]; then
    SB_VAL=$(od -A n -t u1 -j 4 "$SB_VAR" 2>/dev/null | tr -d ' ')
    echo "Secure Boot is now: $( [ "$SB_VAL" = "1" ] && echo ENABLED || echo DISABLED)"
fi
if [ -f "$SM_VAR" ]; then
    SM_VAL=$(od -A n -t u1 -j 4 "$SM_VAR" 2>/dev/null | tr -d ' ')
    echo "Setup Mode is now: $( [ "$SM_VAL" = "1" ] && echo ON || echo OFF)"
fi

# Give OVMF time to write to NVRAM
sleep 2
echo "Powering off..."
poweroff -f
INIT
    chmod +x "$tmpdir/init"

    # Create the initramfs (gzip compressed CPIO)
    cd "$tmpdir"
    find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$PROVISION_INITRAMFS"
    cd - > /dev/null
    rm -rf "$tmpdir"

    info "Provisioning initramfs: ${PROVISION_INITRAMFS} ($(du -h "$PROVISION_INITRAMFS" | cut -f1))"
}

#=============================================================================
# Step 4: Find a kernel for the helper VM
#=============================================================================
find_helper_kernel() {
    # Try to extract from host UKI, or use a system kernel
    if [ -f /boot/EFI/Gentoo/kernel.efi ]; then
        info "Extracting kernel from host UKI..."
        cp /boot/EFI/Gentoo/kernel.efi /tmp/extract-uki.efi 2>/dev/null || true
        if objcopy --dump-section .linux="$PROVISION_KERNEL" /tmp/extract-uki.efi 2>/dev/null; then
            rm -f /tmp/extract-uki.efi
            info "Kernel extracted: $PROVISION_KERNEL"
            return 0
        fi
        rm -f /tmp/extract-uki.efi
    fi

    # Fall back to system kernel
    for k in /boot/vmlinuz-* /boot/vmlinuz; do
        if [ -f "$k" ]; then
            cp "$k" "$PROVISION_KERNEL"
            info "Using system kernel: $k"
            return 0
        fi
    done

    error "No kernel found for helper VM"
}

#=============================================================================
# Step 5: Boot helper VM to provision OVMF NVRAM
#=============================================================================
provision_ovmf() {
    info "Booting helper VM to provision OVMF..."

    # Copy OVMF VARS to writable location
    cp "$OVMF_VARS_TEMPLATE" "${OVMF_DIR}/OVMF_VARS.secboot.fd"

    # Start swtpm
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
    [ -S "$TPM_SOCKET" ] || { cat "${TPM_DIR}/swtpm.log" 2>/dev/null; error "swtpm failed"; }

    info "Starting QEMU for provisioning (30s timeout)..."
    timeout 30 qemu-system-x86_64 \
        -machine q35,smm=on \
        -m 256M \
        -nographic -no-reboot \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="${OVMF_DIR}/OVMF_VARS.secboot.fd" \
        -kernel "$PROVISION_KERNEL" \
        -initrd "$PROVISION_INITRAMFS" \
        -append "console=ttyS0" \
        -chardev socket,id=chrtpm,path="$TPM_SOCKET" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        -serial mon:stdio 2>&1 | tail -30

    kill "$swtpm_pid" 2>/dev/null || true
    wait "$swtpm_pid" 2>/dev/null || true

    info "OVMF NVRAM provisioned: ${OVMF_DIR}/OVMF_VARS.secboot.fd"
    info "Signing keys: ${KEY_DIR}/"
}

#=============================================================================
# Main
#=============================================================================
case "${1:-all}" in
    keys)
        generate_keys ;;
    esl)
        generate_keys
        create_esl_files ;;
    initramfs)
        build_provision_initramfs ;;
    boot)
        build_provision_initramfs
        find_helper_kernel
        provision_ovmf ;;
    all)
        generate_keys
        create_esl_files
        build_provision_initramfs
        find_helper_kernel
        provision_ovmf ;;
    *)
        cat <<HELP
Usage: $0 <step> <test-dir> <ovmf-code> <ovmf-vars-template>

Steps:
  keys       Generate PK/KEK/db key pairs only
  esl        Generate keys + ESL/auth files
  initramfs  Build the provisioning initramfs only
  boot       Build initramfs + boot helper VM to provision
  all        Full provisioning (default)

Output:
  <test-dir>/keys/        - PK/KEK/db keys and certs
  <test-dir>/ovmf/        - Provisioned OVMF_VARS.secboot.fd
HELP
        exit 1 ;;
esac