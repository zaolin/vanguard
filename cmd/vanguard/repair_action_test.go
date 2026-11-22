package main

import (
	"os"
	"strings"
	"testing"
)

// TestRepairTokenUnattendedFailurePrintsManualSteps pins the unattended
// behaviour: with no terminal the repair cannot fall back to a passphrase
// prompt (it would hang the service), so the operator gets explicit
// instructions on stderr and the command still succeeds — the relock
// unit's ExecStartPost (recovery --auto-reseed) must still run.
func TestRepairTokenUnattendedFailurePrintsManualSteps(t *testing.T) {
	origRunner := repairRunner
	origStdin := os.Stdin
	t.Cleanup(func() {
		repairRunner = origRunner
		os.Stdin = origStdin
	})

	// No terminal on stdin: /dev/null is not a tty.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	os.Stdin = devNull

	repairRunner = func(cryptenroll string, args []string) error {
		return os.ErrPermission
	}

	// The token re-read after the failed re-seal must also fail, so the
	// flow takes the "repair failed" branch.
	cmd := &UpdatePolicyCmd{
		LUKSDevice:     "/dev/nvme0n1p2",
		PolicyOutput:   "/boot/EFI/Gentoo/kernel.pcrlock.json",
		UKIPath:        "/boot/EFI/Gentoo/kernel.efi",
		NonInteractive: true,
	}

	// stderr carries the guidance.
	stderr := captureStderr(t, func() {
		if err := cmd.repairToken(0x01919ea9); err != nil {
			t.Errorf("repairToken returned an error in the unattended case: %v", err)
		}
	})

	for _, want := range []string{"vanguard enroll", "/dev/nvme0n1p2"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q missing %q", stderr, want)
		}
	}
}

// TestRepairTokenUsesTPM2UnlockUnattended pins that the unattended path
// unlocks with the existing TPM2 token (no passphrase needed).
func TestRepairTokenUsesTPM2UnlockUnattended(t *testing.T) {
	origRunner := repairRunner
	origStdin := os.Stdin
	t.Cleanup(func() {
		repairRunner = origRunner
		os.Stdin = origStdin
	})

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	os.Stdin = devNull

	var seen []string
	repairRunner = func(cryptenroll string, args []string) error {
		seen = args
		return os.ErrPermission
	}

	cmd := &UpdatePolicyCmd{
		LUKSDevice:     "/dev/nvme0n1p2",
		PolicyOutput:   "/boot/EFI/Gentoo/kernel.pcrlock.json",
		NonInteractive: true,
	}
	_ = cmd.repairToken(0x01919ea9)

	joined := strings.Join(seen, " ")
	if !strings.Contains(joined, "--unlock-tpm2-device=auto") {
		t.Errorf("unattended repair did not use the TPM2 token unlock: %v", seen)
	}
	if strings.Contains(joined, "--unlock-key-file") {
		t.Errorf("unattended repair used an unexpected unlock method: %v", seen)
	}
}

// TestRepairUnlockArgsValidation pins that only real cryptenroll options are
// produced. cryptenroll knows --unlock-key-file, --unlock-fido2-device and
// --unlock-tpm2-device; anything else must be rejected by vanguard rather
// than surfacing as a cryptenroll "Unknown option".
func TestRepairUnlockArgsValidation(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		value      string
		wantArgs   []string
		wantErrSub string
	}{
		{name: "default prompts for the passphrase", wantArgs: nil},
		{name: "password prompts for the passphrase", method: "password", wantArgs: nil},
		{name: "key file", method: "key-file", value: "/etc/vanguard.key", wantArgs: []string{"--unlock-key-file=/etc/vanguard.key"}},
		{name: "tpm2 device", method: "tpm2-device", value: "auto", wantArgs: []string{"--unlock-tpm2-device=auto"}},
		{name: "fido2 device", method: "fido2-device", value: "/dev/hidraw0", wantArgs: []string{"--unlock-fido2-device=/dev/hidraw0"}},
		{name: "empty is not a cryptenroll option", method: "empty", wantErrSub: "unsupported method"},
		{name: "key file needs a value", method: "key-file", wantErrSub: "requires --repair-unlock-value"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &UpdatePolicyCmd{RepairUnlock: tc.method, RepairUnlockValue: tc.value}
			args, err := c.repairUnlockArgs(repairUnlockPassphrase)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("error %q missing %q", err, tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("repairUnlockArgs: %v", err)
			}
			if strings.Join(args, " ") != strings.Join(tc.wantArgs, " ") {
				t.Errorf("args = %v, want %v", args, tc.wantArgs)
			}
		})
	}
}

// TestRepairTokenHonoursExplicitUnlockMethod pins that an explicit
// --repair-unlock selection is carried into the cryptenroll invocation.
func TestRepairTokenHonoursExplicitUnlockMethod(t *testing.T) {
	origRunner := repairRunner
	t.Cleanup(func() { repairRunner = origRunner })

	var seen []string
	repairRunner = func(cryptenroll string, args []string) error {
		seen = args
		return os.ErrPermission
	}

	cmd := &UpdatePolicyCmd{
		LUKSDevice:        "/dev/nvme0n1p2",
		PolicyOutput:      "/boot/EFI/Gentoo/kernel.pcrlock.json",
		RepairUnlock:      "key-file",
		RepairUnlockValue: "/etc/vanguard.key",
	}
	_ = cmd.repairToken(0x01919ea9)

	joined := strings.Join(seen, " ")
	if !strings.Contains(joined, "--unlock-key-file=/etc/vanguard.key") {
		t.Errorf("explicit unlock method not carried into cryptenroll args: %v", seen)
	}
}
