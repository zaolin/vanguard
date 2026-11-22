package luks

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// tokenLoopEnv replaces every external dependency of the token loop and
// records which tokens were attempted.
type tokenLoopEnv struct {
	tried []int
}

func setupTokenLoop(t *testing.T) *tokenLoopEnv {
	t.Helper()

	origNV := nvReadPublic
	origLockout := lockoutStatus
	origPIN := unlockTokenPIN
	origNoPIN := unlockTokenNoPIN
	t.Cleanup(func() {
		nvReadPublic = origNV
		lockoutStatus = origLockout
		unlockTokenPIN = origPIN
		unlockTokenNoPIN = origNoPIN
	})

	env := &tokenLoopEnv{}

	// Defaults: every NV index exists, no lockout, every token fails.
	nvReadPublic = func(tpmClient *intpm.Client, index uint32) error { return nil }
	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return &intpm.LockoutStatus{}, nil
	}
	unlockTokenPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy, attemptsLeft *int) error {
		env.tried = append(env.tried, token.ID)
		return intpm.ErrWrongPIN
	}
	unlockTokenNoPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy) error {
		env.tried = append(env.tried, token.ID)
		return errors.New("no-pin unseal failed")
	}
	return env
}

// TestStaleTokenDoesNotBlockOtherTokens pins that a token whose NV index is
// gone is skipped while the remaining tokens are still tried. Failing the
// whole device because of one stale token would force an unnecessary
// recovery path.
func TestStaleTokenDoesNotBlockOtherTokens(t *testing.T) {
	env := setupTokenLoop(t)

	nvReadPublic = func(tpmClient *intpm.Client, index uint32) error {
		if index == 0x01919ea9 {
			return tpm2.TPMRCHandle // not defined
		}
		return nil
	}
	unlockTokenNoPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy) error {
		env.tried = append(env.tried, token.ID)
		return nil // the second token unlocks
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{
		{ID: 0, UsePCRLock: true, PCRLockNV: 0x01919ea9},
		{ID: 1},
	}

	budget := maxPINAttempts
	if err := d.tryTokens(nil, tokens, nil, &budget); err != nil {
		t.Fatalf("the second token was not used: %v", err)
	}
	if len(env.tried) != 1 || env.tried[0] != 1 {
		t.Errorf("attempted tokens = %v, want only token 1", env.tried)
	}
}

// TestAllTokensStaleReportsReenroll pins that the actionable stale-index
// error survives when no token can unlock the device.
func TestAllTokensStaleReportsReenroll(t *testing.T) {
	env := setupTokenLoop(t)
	_ = env

	nvReadPublic = func(tpmClient *intpm.Client, index uint32) error {
		return tpm2.TPMRCHandle
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, UsePCRLock: true, PCRLockNV: 0x01919ea9}}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if !errors.Is(err, intpm.ErrTokenStaleNVIndex) {
		t.Errorf("err = %v, want ErrTokenStaleNVIndex", err)
	}
}

// TestPINLessTokenStillTriedWhenBudgetSpent pins that the PIN budget gates
// only PIN-bearing tokens: a PIN-less token consumes no dictionary-attack
// attempt and must still be tried.
func TestPINLessTokenStillTriedWhenBudgetSpent(t *testing.T) {
	env := setupTokenLoop(t)

	unlockTokenPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy, attemptsLeft *int) error {
		env.tried = append(env.tried, token.ID)
		*attemptsLeft = 0 // the attempt consumed the last budget unit
		return intpm.ErrWrongPIN
	}
	unlockTokenNoPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy) error {
		env.tried = append(env.tried, token.ID)
		return nil
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1}}

	budget := 1
	if err := d.tryTokens(nil, tokens, nil, &budget); err != nil {
		t.Fatalf("the PIN-less token was not used: %v", err)
	}
	if len(env.tried) != 2 || env.tried[1] != 1 {
		t.Errorf("attempted tokens = %v, want both tokens", env.tried)
	}
}

// TestPINBudgetSkipsOnlyPINTokens pins the other direction: with the budget
// spent, a PIN-bearing token is skipped while a PIN-less one still runs.
func TestPINBudgetSkipsOnlyPINTokens(t *testing.T) {
	env := setupTokenLoop(t)

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1, NeedsPIN: true}, {ID: 2}}

	budget := 0
	_ = d.tryTokens(nil, tokens, nil, &budget)
	if len(env.tried) != 1 || env.tried[0] != 2 {
		t.Errorf("attempted tokens = %v, want only the PIN-less token 2", env.tried)
	}
}

// TestLockoutStatusErrorStopsPINAttempts pins the fail-safe behaviour: when
// the TPM's lockout state cannot be read after a failed PIN attempt, no
// further PIN authorization is issued — but a PIN-less token is still tried.
func TestLockoutStatusErrorStopsPINAttempts(t *testing.T) {
	env := setupTokenLoop(t)

	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return nil, errors.New("transport failure")
	}
	unlockTokenNoPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy) error {
		env.tried = append(env.tried, token.ID)
		return nil
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1, NeedsPIN: true}, {ID: 2}}

	budget := maxPINAttempts
	if err := d.tryTokens(nil, tokens, nil, &budget); err != nil {
		t.Fatalf("the PIN-less token was not used: %v", err)
	}
	if len(env.tried) != 2 || env.tried[0] != 0 || env.tried[1] != 2 {
		t.Errorf("attempted tokens = %v, want token 0 and the PIN-less token 2", env.tried)
	}
}

// TestStaleErrorSurvivesLaterOrdinaryFailure pins the error precedence: the
// actionable re-enroll instruction must not be replaced by a later, less
// specific failure on another token.
func TestStaleErrorSurvivesLaterOrdinaryFailure(t *testing.T) {
	setupTokenLoop(t)

	nvReadPublic = func(tpmClient *intpm.Client, index uint32) error {
		return tpm2.TPMRCHandle // the first token's index is gone
	}
	// The second (PIN-less) token fails with an ordinary error.
	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{
		{ID: 0, UsePCRLock: true, PCRLockNV: 0x01919ea9},
		{ID: 1},
	}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if !errors.Is(err, intpm.ErrTokenStaleNVIndex) {
		t.Errorf("err = %v, want ErrTokenStaleNVIndex to survive", err)
	}
}

// TestLockoutReadErrorSurvivesLaterFailures pins that a lockout-state read
// failure is not overwritten by the budget skip or by a later PIN-less
// failure — the user must learn that the TPM state is unknown.
func TestLockoutReadErrorSurvivesLaterFailures(t *testing.T) {
	setupTokenLoop(t)

	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return nil, errors.New("transport failure")
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{
		{ID: 0, NeedsPIN: true},
		{ID: 1, NeedsPIN: true}, // skipped: the budget was zeroed
		{ID: 2},                 // fails with an ordinary error
	}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if err == nil || !strings.Contains(err.Error(), "lockout state") {
		t.Errorf("err = %v, want the lockout-state error to survive", err)
	}
}

// TestUnsealLockoutStopsLoopAndWins pins that a lockout reported by the unseal
// itself stops the token loop immediately and is the reported error — the user
// needs the lockout/recovery guidance, not a re-enroll hint or a later,
// unspecific failure.
func TestUnsealLockoutStopsLoopAndWins(t *testing.T) {
	env := setupTokenLoop(t)

	unlockTokenPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy, attemptsLeft *int) error {
		env.tried = append(env.tried, token.ID)
		return intpm.ErrTPMLockout
	}
	// The status read fails afterwards and must not replace the known lockout.
	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return nil, errors.New("transport failure")
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1, NeedsPIN: true}}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if !errors.Is(err, intpm.ErrTPMLockout) {
		t.Errorf("err = %v, want ErrTPMLockout", err)
	}
	if len(env.tried) != 1 {
		t.Errorf("attempted tokens = %v, want only token 0 (a lockout stops the loop)", env.tried)
	}
}

// TestLockoutOutranksStaleToken pins the error priority: a real TPM lockout is
// more urgent than a stale-token re-enrollment hint seen earlier.
func TestLockoutOutranksStaleToken(t *testing.T) {
	setupTokenLoop(t)

	nvReadPublic = func(tpmClient *intpm.Client, index uint32) error {
		return tpm2.TPMRCHandle // the first token's index is gone
	}
	unlockTokenPIN = func(d *Device, tpmClient *intpm.Client, token *TPM2Token, pcrlockPolicy *intpm.PCRLockPolicy, attemptsLeft *int) error {
		return intpm.ErrTPMLockout
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{
		{ID: 0, UsePCRLock: true, PCRLockNV: 0x01919ea9},
		{ID: 1, NeedsPIN: true},
	}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if !errors.Is(err, intpm.ErrTPMLockout) {
		t.Errorf("err = %v, want ErrTPMLockout to outrank the stale-token error", err)
	}
}

// TestTokenLoopStopsOnRealLockout pins that a TPM lockout is reported
// instead of trying further tokens.
func TestTokenLoopStopsOnRealLockout(t *testing.T) {
	env := setupTokenLoop(t)

	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return &intpm.LockoutStatus{InLockout: true}, nil
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1, NeedsPIN: true}}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if !errors.Is(err, intpm.ErrTPMLockout) {
		t.Errorf("err = %v, want ErrTPMLockout", err)
	}
	if len(env.tried) != 1 {
		t.Errorf("attempted tokens = %v, want only token 0", env.tried)
	}
}
