#!/bin/bash
# Helper script for TPM enrollment (runs as root)
set -e

DISK_IMG="$1"
DISK_RAW="$2"
TPM_SOCKET="$3"
LUKS_PASS="$4"
PCRLOCK_JSON="$5"
TPM_PIN="$6"

qemu-img convert -f qcow2 -O raw "${DISK_IMG}" "${DISK_RAW}"
LOOP=$(losetup -f --show "${DISK_RAW}")
partprobe "$LOOP"; sleep 1
# LUKS partition is on p2 (p1 is /boot)
PART="${LOOP}p2"; [ -e "$PART" ] || PART="${LOOP}p1"

PASSFILE=$(mktemp)
echo -n "${LUKS_PASS}" > "$PASSFILE"

# Build cryptenroll arguments
ENROLL_ARGS=(
    --tpm2-device="swtpm:path=${TPM_SOCKET}"
    --tpm2-pcrs=
    --wipe-slot=tpm2
    --unlock-key-file="$PASSFILE"
)

# Add pcrlock policy if provided
if [ -n "$PCRLOCK_JSON" ] && [ -f "$PCRLOCK_JSON" ]; then
    ENROLL_ARGS+=(--tpm2-pcrlock="$PCRLOCK_JSON")
    echo "Enrolling with pcrlock policy: $PCRLOCK_JSON"
else
    ENROLL_ARGS+=(--tpm2-pcrlock=)
    echo "Enrolling without pcrlock policy"
fi

# Add PIN if requested
if [ -n "$TPM_PIN" ]; then
    ENROLL_ARGS+=(--tpm2-with-pin=yes)
    echo ""
    echo "=================================================="
    echo "TPM PIN enrollment requested."
    echo "When prompted, enter PIN: ${TPM_PIN}"
    echo "You can use: systemd-tty-ask-password-agent --query"
    echo "=================================================="
    echo ""
fi

systemd-cryptenroll "${ENROLL_ARGS[@]}" "$PART"

rm -f "$PASSFILE"
losetup -d "$LOOP"
qemu-img convert -f raw -O qcow2 "${DISK_RAW}" "${DISK_IMG}"
rm -f "${DISK_RAW}"
