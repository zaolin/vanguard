package luks

import (
	"errors"
	"testing"

	"github.com/zaolin/vanguard/init/tui"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// promptRouterEnv replaces the low-level prompt seams so the production
// routing (defaultPromptForSecret) can be driven without a TUI or a console.
type promptRouterEnv struct {
	tuiCalls     int
	consoleCalls int
}

func setupPromptRouter(t *testing.T) *promptRouterEnv {
	t.Helper()

	origAvailable := tuiPromptAvailable
	origPassword := tuiPromptPassword
	origConsole := consoleReadSecret
	t.Cleanup(func() {
		tuiPromptAvailable = origAvailable
		tuiPromptPassword = origPassword
		consoleReadSecret = origConsole
	})

	env := &promptRouterEnv{}
	tuiPromptAvailable = func() bool { return false }
	tuiPromptPassword = func(string) (string, error) {
		env.tuiCalls++
		return "", tui.ErrPromptUnavailable
	}
	consoleReadSecret = func(string) (string, error) {
		env.consoleCalls++
		return "console-secret", nil
	}
	return env
}

// TestPromptForSecretFallsBackToConsoleWhenTUIIsDead pins the routing
// decision that broke the post-HOTP passphrase fallback: when the TUI is not
// live, the prompt must go to the console instead of failing with "TUI not
// initialized".
func TestPromptForSecretFallsBackToConsoleWhenTUIIsDead(t *testing.T) {
	env := setupPromptRouter(t)

	got, err := defaultPromptForSecret("tui prompt", "console prompt")
	if err != nil {
		t.Fatalf("defaultPromptForSecret: %v", err)
	}
	if got != "console-secret" {
		t.Errorf("secret = %q, want the console result", got)
	}
	if env.consoleCalls != 1 || env.tuiCalls != 0 {
		t.Errorf("console calls = %d, tui calls = %d, want 1 and 0", env.consoleCalls, env.tuiCalls)
	}
}

// TestPromptForSecretUsesTUIWhenAlive pins the other direction: with a live
// TUI the prompt must go to the TUI, not the console.
func TestPromptForSecretUsesTUIWhenAlive(t *testing.T) {
	env := setupPromptRouter(t)

	tuiPromptAvailable = func() bool { return true }
	tuiPromptPassword = func(string) (string, error) {
		env.tuiCalls++
		return "tui-secret", nil
	}

	got, err := defaultPromptForSecret("tui prompt", "console prompt")
	if err != nil {
		t.Fatalf("defaultPromptForSecret: %v", err)
	}
	if got != "tui-secret" {
		t.Errorf("secret = %q, want the TUI result", got)
	}
	if env.tuiCalls != 1 || env.consoleCalls != 0 {
		t.Errorf("tui calls = %d, console calls = %d, want 1 and 0", env.tuiCalls, env.consoleCalls)
	}
}

// TestPromptForSecretFallsBackWhenTUIDiesMidPrompt pins the liveness race:
// the TUI can exit between the availability check and the prompt. The prompt
// must then be retried on the console instead of failing the unlock.
func TestPromptForSecretFallsBackWhenTUIDiesMidPrompt(t *testing.T) {
	env := setupPromptRouter(t)

	tuiPromptAvailable = func() bool { return true }
	tuiPromptPassword = func(string) (string, error) {
		env.tuiCalls++
		return "", tui.ErrPromptUnavailable
	}

	got, err := defaultPromptForSecret("tui prompt", "console prompt")
	if err != nil {
		t.Fatalf("defaultPromptForSecret: %v", err)
	}
	if got != "console-secret" {
		t.Errorf("secret = %q, want the console fallback", got)
	}
	if env.tuiCalls != 1 || env.consoleCalls != 1 {
		t.Errorf("tui calls = %d, console calls = %d, want 1 and 1", env.tuiCalls, env.consoleCalls)
	}
}

// TestPromptForSecretDoesNotFallbackOnOtherErrors pins that a real prompt
// error (not a dead TUI) is propagated instead of silently re-prompting on
// the console.
func TestPromptForSecretDoesNotFallbackOnOtherErrors(t *testing.T) {
	env := setupPromptRouter(t)

	tuiPromptAvailable = func() bool { return true }
	boom := errors.New("prompt I/O failure")
	tuiPromptPassword = func(string) (string, error) {
		env.tuiCalls++
		return "", boom
	}

	_, err := defaultPromptForSecret("tui prompt", "console prompt")
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the prompt error", err)
	}
	if env.consoleCalls != 0 {
		t.Error("the console was used although the TUI failed for a non-liveness reason")
	}
}

// TestPromptForSecretEmptyEntryIsNotATUIError pins that an empty TUI result
// (the user cancelled) is passed through, not retried on the console.
func TestPromptForSecretEmptyEntryIsNotATUIError(t *testing.T) {
	env := setupPromptRouter(t)

	tuiPromptAvailable = func() bool { return true }
	tuiPromptPassword = func(string) (string, error) {
		env.tuiCalls++
		return "", nil
	}

	got, err := defaultPromptForSecret("tui prompt", "console prompt")
	if err != nil {
		t.Fatalf("defaultPromptForSecret: %v", err)
	}
	if got != "" {
		t.Errorf("secret = %q, want empty (user cancel)", got)
	}
	if env.consoleCalls != 0 {
		t.Error("a cancelled TUI prompt must not be retried on the console")
	}
}

// TestMultiTokenRetryStopsOnCancel pins that a cancelled PIN prompt stops
// the whole token loop instead of re-prompting for every remaining token:
// the user pressed ctrl+c, so asking again is wrong.
//
// The production loop is driven through tryTokens with two tokens, so the
// short-circuit in the loop itself is covered.
func TestMultiTokenRetryStopsOnCancel(t *testing.T) {
	origUnseal := unsealWithPIN
	origPrompt := promptForSecretImpl
	t.Cleanup(func() {
		unsealWithPIN = origUnseal
		promptForSecretImpl = origPrompt
	})

	prompts := 0
	promptForSecretImpl = func(tuiPrompt, consolePrompt string) (string, error) {
		prompts++
		return "", nil // empty PIN = user cancel
	}
	unsealWithPIN = func(token *TPM2Token, tpmClient *intpm.Client, pin []byte, pcrlockPolicy *intpm.PCRLockPolicy) ([]byte, error) {
		t.Error("unseal must not be attempted after a cancel")
		return nil, nil
	}

	d := &Device{Path: "/dev/test0"}
	// Two PIN tokens: the loop must stop after the first cancel.
	tokens := []*TPM2Token{{ID: 0, NeedsPIN: true}, {ID: 1, NeedsPIN: true}}

	budget := maxPINAttempts
	err := d.tryTokens(nil, tokens, nil, &budget)
	if !errors.Is(err, errPINCancelled) {
		t.Errorf("err = %v, want errPINCancelled", err)
	}
	if prompts != 1 {
		t.Errorf("PIN prompts = %d, want 1 (the cancel must stop the loop)", prompts)
	}
}
