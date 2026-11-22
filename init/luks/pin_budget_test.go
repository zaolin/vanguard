package luks

import (
	"errors"
	"testing"
	"time"

	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// TestSharedPINBudgetIsSpentByProductionCode pins that the shared PIN
// attempt budget is really consumed by the unlock path and that the
// production code refuses further attempts once it is spent.
//
// The budget exists because the TPM's dictionary-attack counter is
// per-TPM (measured maxAuthFail=3 on swtpm) while a per-token or
// per-device budget would allow 3*N attempts and lock the TPM out from a
// single mistyped PIN.
func TestSharedPINBudgetIsSpentByProductionCode(t *testing.T) {
	origUnseal := unsealWithPIN
	origPrompt := promptForSecretImpl
	t.Cleanup(func() {
		unsealWithPIN = origUnseal
		promptForSecretImpl = origPrompt
	})

	attempts := 0
	unsealWithPIN = func(token *TPM2Token, tpmClient *intpm.Client, pin []byte, pcrlockPolicy *intpm.PCRLockPolicy) ([]byte, error) {
		attempts++
		return nil, intpm.ErrWrongPIN
	}
	// The PIN prompt always answers with a non-empty value so the path
	// is not aborted as a cancel.
	promptForSecretImpl = func(tuiPrompt, consolePrompt string) (string, error) {
		return "1234", nil
	}

	d := &Device{Path: "/dev/test0"}
	token := &TPM2Token{NeedsPIN: true}

	budget := maxPINAttempts
	err := d.unlockWithTPM2PIN(nil, token, nil, &budget)
	if err == nil {
		t.Fatal("expected the unlock to fail with a wrong PIN")
	}
	if attempts != maxPINAttempts {
		t.Errorf("unseal attempts = %d, want %d", attempts, maxPINAttempts)
	}
	if budget != 0 {
		t.Errorf("budget after the attempts = %d, want 0", budget)
	}
}

// TestSharedPINBudgetStopsFurtherTokens pins that a second token does not
// get a fresh budget: with the budget spent, the production code must
// refuse to prompt again instead of risking a TPM lockout.
func TestSharedPINBudgetStopsFurtherTokens(t *testing.T) {
	origUnseal := unsealWithPIN
	origPrompt := promptForSecretImpl
	t.Cleanup(func() {
		unsealWithPIN = origUnseal
		promptForSecretImpl = origPrompt
	})

	attempts := 0
	unsealWithPIN = func(token *TPM2Token, tpmClient *intpm.Client, pin []byte, pcrlockPolicy *intpm.PCRLockPolicy) ([]byte, error) {
		attempts++
		return nil, intpm.ErrWrongPIN
	}
	promptForSecretImpl = func(tuiPrompt, consolePrompt string) (string, error) {
		return "1234", nil
	}

	d := &Device{Path: "/dev/test0"}
	token := &TPM2Token{NeedsPIN: true}

	budget := 0 // already spent
	err := d.unlockWithTPM2PIN(nil, token, nil, &budget)
	if !errors.Is(err, errPINBudgetExhausted) {
		t.Fatalf("err = %v, want errPINBudgetExhausted", err)
	}
	if attempts != 0 {
		t.Errorf("unseal attempts = %d, want 0 (the budget was spent)", attempts)
	}
}

// TestSharedBudgetSpansTokens pins that the token loop does not hand out a
// fresh budget per token: once the shared budget is spent, no further token
// is tried.
func TestSharedBudgetSpansTokens(t *testing.T) {
	origUnseal := unsealWithPIN
	origPrompt := promptForSecretImpl
	origLockout := lockoutStatus
	t.Cleanup(func() {
		unsealWithPIN = origUnseal
		promptForSecretImpl = origPrompt
		lockoutStatus = origLockout
	})
	// The token loop re-reads the TPM lockout state after a failed PIN
	// token; there is no TPM here.
	lockoutStatus = func(tpmClient *intpm.Client) (*intpm.LockoutStatus, error) {
		return &intpm.LockoutStatus{}, nil
	}

	attempts := 0
	prompts := 0
	unsealWithPIN = func(token *TPM2Token, tpmClient *intpm.Client, pin []byte, pcrlockPolicy *intpm.PCRLockPolicy) ([]byte, error) {
		attempts++
		return nil, intpm.ErrWrongPIN
	}
	promptForSecretImpl = func(tuiPrompt, consolePrompt string) (string, error) {
		prompts++
		return "1234", nil
	}

	d := &Device{Path: "/dev/test0"}
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1, NeedsPIN: true}}

	budget := 1 // a single attempt left for the whole TPM
	err := d.tryTokens(nil, tokens, nil, &budget)
	if err == nil {
		t.Fatal("expected the unlock to fail")
	}
	if attempts != 1 {
		t.Errorf("unseal attempts = %d, want 1 (the shared budget must not reset per token)", attempts)
	}
	if prompts != 1 {
		t.Errorf("PIN prompts = %d, want 1 (the second token must not be prompted)", prompts)
	}
}

// TestPINBudgetNilMeansFreshBudget pins the documented nil contract: a
// caller that passes no budget gets a fresh one instead of a nil-pointer
// panic in PID 1.
func TestPINBudgetNilMeansFreshBudget(t *testing.T) {
	origUnseal := unsealWithPIN
	origPrompt := promptForSecretImpl
	t.Cleanup(func() {
		unsealWithPIN = origUnseal
		promptForSecretImpl = origPrompt
	})

	attempts := 0
	unsealWithPIN = func(token *TPM2Token, tpmClient *intpm.Client, pin []byte, pcrlockPolicy *intpm.PCRLockPolicy) ([]byte, error) {
		attempts++
		return nil, intpm.ErrWrongPIN
	}
	promptForSecretImpl = func(tuiPrompt, consolePrompt string) (string, error) {
		return "1234", nil
	}

	d := &Device{Path: "/dev/test0"}
	if err := d.unlockWithTPM2PIN(nil, &TPM2Token{NeedsPIN: true}, nil, nil); err == nil {
		t.Fatal("expected the unlock to fail with a wrong PIN")
	}
	if attempts != maxPINAttempts {
		t.Errorf("unseal attempts = %d, want %d", attempts, maxPINAttempts)
	}
}

// TestPINBudgetExhaustionMessage ensures the user gets an explanation when
// the budget is spent, instead of a bare TPM error.
func TestPINBudgetExhaustionMessage(t *testing.T) {
	msg := errPINBudgetExhausted.Error()
	for _, want := range []string{"budget", "dictionary-attack"} {
		if !contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}

// TestErrorMinDisplayStillTwoSeconds guards the readability requirement
// against accidental changes.
func TestErrorMinDisplayStillTwoSeconds(t *testing.T) {
	if errorMinDisplay < 2*time.Second {
		t.Errorf("errorMinDisplay = %v, want >= 2s", errorMinDisplay)
	}
}
