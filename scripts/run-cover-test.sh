#!/bin/bash
# Coverage test: build covered init, run QEMU, collect coverage, report.
# Requires root for losetup, cryptsetup, and KVM access.
set -e
cd "$(dirname "$0")/.."

TPM_SOCKET="test/tpm/swtpm.sock"
TPM_DIR="test/tpm"
KERNEL="testdata/kernel/bzImage"
LUKS_PASS="testpass"
TPM_PIN="1234"

# Kill any existing swtpm
pkill -f "swtpm socket.*${TPM_SOCKET}" 2>/dev/null || true
sleep 0.3
rm -f "${TPM_SOCKET}" "${TPM_SOCKET}.ctrl"

# Check kernel exists
if [ ! -f "${KERNEL}" ]; then
    echo "ERROR: Kernel not found at ${KERNEL}"
    echo "Run: scripts/helpers/build-test-kernel.sh"
    exit 1
fi

# Check if we're root
if [ "$(id -u)" -ne 0 ]; then
    echo "WARNING: not running as root — TPM enrollment and disk creation will be skipped"
    echo "         Run as root for full coverage. Continuing with go test only..."
    go test -coverprofile=test/gotest.out ./... 2>&1 | tail -3
    go tool cover -func=test/gotest.out | tail -1
    exit 0
fi

# Step 1: Build vanguard + covered init + C wrapper
echo "[INFO] Building vanguard..."
go build -o vanguard ./cmd/vanguard/

echo "[INFO] Building covered init..."
CGO_ENABLED=0 go build -cover -tags debug -o test/init-cover ./init/
gcc -static -o /tmp/init-cover-wrapper scripts/helpers/init-cover-wrapper.c

# Step 2: Create test disk (if not exists)
if [ ! -f test/test-disk.raw ]; then
    echo "[INFO] Creating test disk..."
    dd if=/dev/zero of=test/test-disk.raw bs=1G count=1
    scripts/helpers/create-disk.sh test/test-disk.raw "${LUKS_PASS}"
fi

# Step 3: Enroll TPM (fresh swtpm state)
echo "[INFO] Starting swtpm for enrollment..."
rm -rf "${TPM_DIR}"
mkdir -p "${TPM_DIR}"
swtpm socket --tpmstate dir="${TPM_DIR}" \
    --server type=unixio,path="${TPM_SOCKET}" \
    --ctrl type=unixio,path="${TPM_SOCKET}.ctrl" \
    --tpm2 --flags startup-clear,not-need-init &
SWTPM_PID=$!
cleanup() { kill ${SWTPM_PID} 2>/dev/null || true; wait ${SWTPM_PID} 2>/dev/null || true; }
trap cleanup EXIT
sleep 1
[ -S "${TPM_SOCKET}" ] || { echo "ERROR: swtpm failed"; exit 1; }

echo "[INFO] Enrolling TPM token..."
LOOP=$(losetup -f --show test/test-disk.raw)
partprobe ${LOOP}; sleep 1
PART="${LOOP}p2"; [ -e "${PART}" ] || PART="${LOOP}p1"

echo -n "${LUKS_PASS}" | systemd-cryptenroll \
    --tpm2-device="swtpm:path=${TPM_SOCKET}" \
    --wipe-slot=tpm2 --wipe-slot=tpm2 \
    --unlock-key-file=/dev/stdin "${PART}"

echo "[INFO] Generating pcrlock policy..."
SYSTEMD_TPM2_DEVICE="swtpm:path=${TPM_SOCKET}" \
    systemd-pcrlock make-policy --policy=test/pcrlock.json --pcr=23 --force 2>&1 || true

echo "[INFO] Stopping swtpm (preserving state)..."
kill ${SWTPM_PID}; wait ${SWTPM_PID} 2>/dev/null || true
losetup -d ${LOOP}
trap - EXIT

# Step 4: Generate initramfs with covered init
echo "[INFO] Generating initramfs..."
./vanguard generate -o test/initramfs.img --debug --init-binary test/init-cover

# Step 5: Create ext4 cover disk
echo "[INFO] Creating cover disk..."
dd if=/dev/zero of=test/cover.img bs=1M count=10 2>/dev/null
mkfs.ext4 -q test/cover.img

# Step 6: Restart swtpm in ctrl-only mode (QEMU needs the ctrl socket, not --server)
echo "[INFO] Restarting swtpm (ctrl-only, preserving NV indexes)..."
swtpm socket --tpmstate dir="${TPM_DIR}" \
    --ctrl type=unixio,path="${TPM_DIR}/swtpm-qemu.sock" \
    --tpm2 --flags startup-none,not-need-init \
    --log level=5,file="${TPM_DIR}/swtpm-qemu.log" &
SWTPM_PID=$!
cleanup() { kill ${SWTPM_PID} 2>/dev/null || true; wait ${SWTPM_PID} 2>/dev/null || true; }
trap cleanup EXIT
sleep 1
QEMU_TPM_SOCKET="${TPM_DIR}/swtpm-qemu.sock"
[ -S "${QEMU_TPM_SOCKET}" ] || { echo "ERROR: swtpm restart failed"; cat "${TPM_DIR}/swtpm-qemu.log" 2>/dev/null; exit 1; }

# Step 7: Run QEMU with coverage collection
echo "[INFO] Starting QEMU for coverage collection..."
timeout 120 qemu-system-x86_64 \
    -m 512M -cpu host -enable-kvm \
    -kernel "${KERNEL}" \
    -initrd test/initramfs.img \
    -append "root=/dev/vg0/root console=ttyS0 vanguard.testmode=1 panic=1 GOCOVERDIR=/cover" \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0,bus=scsi0.0 \
    -drive file=test/test-disk.raw,format=raw,id=hd0,if=none \
    -drive id=cover,format=raw,if=none,file=test/cover.img \
    -device virtio-blk-pci,drive=cover \
    -chardev socket,id=chrtpm,path="${QEMU_TPM_SOCKET}" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -nographic -no-reboot 2>&1 | tee test/cover-boot.log

# Step 8: Extract QEMU coverage
echo "[INFO] Extracting coverage data..."
rm -rf test/cover-data && mkdir -p test/cover-data
for f in $(e2ls test/cover.img 2>/dev/null | grep -v lost+found | tr -d ' '); do
    e2cp "test/cover.img:/$f" "test/cover-data/$f" 2>/dev/null
done

COVER_FILES=$(ls test/cover-data/ 2>/dev/null | wc -l)
echo "[INFO] Found ${COVER_FILES} coverage files"

if [ "${COVER_FILES}" -gt 0 ]; then
    echo "[INFO] Converting QEMU coverage to text format..."
    go tool covdata textfmt -i test/cover-data -o test/qemu-cover.out 2>/dev/null
    echo "[INFO] QEMU coverage:"
    go tool cover -func=test/qemu-cover.out 2>&1 | tail -1
else
    echo "[WARN] No QEMU coverage data collected"
fi

# Step 9: Run go test coverage
echo "[INFO] Running go test coverage..."
go test -coverprofile=test/gotest.out ./... 2>&1 | tail -3
echo "[INFO] Go test coverage:"
go tool cover -func=test/gotest.out 2>&1 | tail -1

# Step 10: Report
echo ""
echo "=== Combined Coverage ==="
if [ -f test/qemu-cover.out ]; then
    echo "QEMU boot coverage:"
    go tool cover -func=test/qemu-cover.out 2>&1 | tail -1
fi
if [ -f test/gotest.out ]; then
    echo "Go test coverage:"
    go tool cover -func=test/gotest.out 2>&1 | tail -1
fi