package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

// repairEnv captures the side effects of a repair run: the cryptenroll
// invocations and the PCR 11 prediction refreshes.
type repairEnv struct {
	runs       int
	injections int
	policyPath string
	tokenBlob  string
}

// setupRepairEnv drives repairToken with every external dependency replaced.
// tokenBlob is the NV handle blob the token carries after the re-seal; the
// policy is written with the same blob so a "match" is possible.
func setupRepairEnv(t *testing.T) *repairEnv {
	t.Helper()

	env := &repairEnv{}
	env.tokenBlob = base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})

	dir := t.TempDir()
	env.policyPath = filepath.Join(dir, "kernel.pcrlock.json")
	policy := map[string]interface{}{
		"nvIndex":   0x01919ea9,
		"nvHandle":  env.tokenBlob,
		"pcrValues": []interface{}{},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.policyPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	origRunner := repairRunner
	origToken := getLUKSTPMToken
	origInject := injectHeaderPrediction
	origLookPath := cryptenrollLookPath
	origTerminal := stdinIsTerminal
	t.Cleanup(func() {
		repairRunner = origRunner
		getLUKSTPMToken = origToken
		injectHeaderPrediction = origInject
		cryptenrollLookPath = origLookPath
		stdinIsTerminal = origTerminal
	})

	cryptenrollLookPath = func() (string, error) { return "/usr/bin/systemd-cryptenroll", nil }
	stdinIsTerminal = func() bool { return true }

	repairRunner = func(string, []string) error {
		env.runs++
		return nil
	}
	getLUKSTPMToken = func(string) (*pcrlock.LUKSTPMToken, error) {
		return &pcrlock.LUKSTPMToken{NVIndex: 0x01919ea9, NVHandle: env.tokenBlob, HasPCRLock: true}, nil
	}
	injectHeaderPrediction = func(policyPath, devicePath string) error {
		env.injections++
		return nil
	}
	return env
}

// TestRepairSuccessRefreshesHeaderPrediction pins the ordering constraint:
// the re-seal rewrites the LUKS2 JSON metadata, so the PCR 11 prediction must
// be refreshed AFTER the repair, not only before it.
func TestRepairSuccessRefreshesHeaderPrediction(t *testing.T) {
	env := setupRepairEnv(t)

	cmd := &UpdatePolicyCmd{
		LUKSDevice:        "/dev/nvme0n1p2",
		PolicyOutput:      env.policyPath,
		luksHeaderEnabled: true,
	}
	if err := cmd.repairToken(0x01919ea9); err != nil {
		t.Fatalf("repairToken: %v", err)
	}
	if env.runs != 1 {
		t.Errorf("cryptenroll runs = %d, want 1", env.runs)
	}
	if env.injections != 1 {
		t.Errorf("prediction refreshes = %d, want 1 (the re-seal changed the LUKS header)", env.injections)
	}
}

// TestRepairConfirmationRejectsClassicToken pins that "not stale" is not
// accepted as a successful repair: a token without a pcrlock binding cannot
// confirm a pcrlock repair.
func TestRepairConfirmationRejectsClassicToken(t *testing.T) {
	env := setupRepairEnv(t)

	getLUKSTPMToken = func(string) (*pcrlock.LUKSTPMToken, error) {
		// A classic PCR-bound token: no NV binding at all.
		return &pcrlock.LUKSTPMToken{}, nil
	}

	cmd := &UpdatePolicyCmd{LUKSDevice: "/dev/nvme0n1p2", PolicyOutput: env.policyPath}
	err := cmd.repairToken(0x01919ea9)
	if err == nil {
		t.Fatal("expected the confirmation to reject a non-pcrlock token")
	}
	if !strings.Contains(err.Error(), "want a pcrlock-bound match") {
		t.Errorf("error %q does not explain the missing binding", err)
	}
	if env.injections != 0 {
		t.Error("the prediction must not be refreshed when the repair is unconfirmed")
	}
}

// TestRepairConfirmationRejectsStaleToken pins that a token which is still
// stale after the re-seal is reported as a failure.
func TestRepairConfirmationRejectsStaleToken(t *testing.T) {
	env := setupRepairEnv(t)

	getLUKSTPMToken = func(string) (*pcrlock.LUKSTPMToken, error) {
		other := base64.StdEncoding.EncodeToString([]byte{0x09})
		return &pcrlock.LUKSTPMToken{NVIndex: 0x01919ea9, NVHandle: other, HasPCRLock: true}, nil
	}

	cmd := &UpdatePolicyCmd{LUKSDevice: "/dev/nvme0n1p2", PolicyOutput: env.policyPath}
	if err := cmd.repairToken(0x01919ea9); err == nil {
		t.Fatal("expected an error when the token is still stale")
	}
}

// TestRepairRetrySuccessAlsoVerifies pins that a successful TPM-token retry
// runs the same confirmation and prediction refresh as a first-attempt
// success.
func TestRepairRetrySuccessAlsoVerifies(t *testing.T) {
	env := setupRepairEnv(t)

	repairRunner = func(string, []string) error {
		env.runs++
		if env.runs == 1 {
			return os.ErrPermission // the first (passphrase) attempt fails
		}
		return nil
	}

	cmd := &UpdatePolicyCmd{
		LUKSDevice:        "/dev/nvme0n1p2",
		PolicyOutput:      env.policyPath,
		luksHeaderEnabled: true,
		RepairUnlock:      "key-file",
		RepairUnlockValue: "/etc/vanguard.key",
	}
	if err := cmd.repairToken(0x01919ea9); err != nil {
		t.Fatalf("repairToken: %v", err)
	}
	if env.runs != 2 {
		t.Errorf("cryptenroll runs = %d, want 2 (initial attempt + retry)", env.runs)
	}
	if env.injections != 1 {
		t.Errorf("prediction refreshes = %d, want 1 after the retry", env.injections)
	}
}

// TestRepairRetryFailureIsReported pins that a failed retry does not claim
// success.
func TestRepairRetryFailureIsReported(t *testing.T) {
	env := setupRepairEnv(t)

	repairRunner = func(string, []string) error {
		env.runs++
		return os.ErrPermission
	}

	cmd := &UpdatePolicyCmd{
		LUKSDevice:        "/dev/nvme0n1p2",
		PolicyOutput:      env.policyPath,
		RepairUnlock:      "key-file",
		RepairUnlockValue: "/etc/vanguard.key",
	}
	if err := cmd.repairToken(0x01919ea9); err == nil {
		t.Fatal("expected an error when both attempts fail")
	}
	if env.injections != 0 {
		t.Error("no prediction refresh may happen after a failed repair")
	}
}
