package tpm

import (
	"errors"
	"fmt"
	"testing"
)

// TestPCRLockUnsealClassifiesAsPolicyFailed pins the error-oracle
// protection for pcrlock tokens.
//
// unsealWithPCRLock must collapse a wrong PIN and a broken PCR chain into
// ErrPolicyFailed. The call site used to pass usePCRLock=false, which
// classified a mistyped PIN as ErrPCRMismatch — defeating the oracle
// protection and making the initrd skip the PIN retry while telling the
// user their "system configuration changed".
func TestPCRLockUnsealClassifiesAsPolicyFailed(t *testing.T) {
	cases := []struct {
		name string
		raw  error
	}{
		{"auth fail", fmt.Errorf("TPM_RC_AUTH_FAIL")},
		{"policy fail", fmt.Errorf("TPM_RC_POLICY_FAIL")},
		{"bad auth", fmt.Errorf("TPM_RC_BAD_AUTH")},
		{"string matched auth", fmt.Errorf("HMAC check failed")},
		{"string matched policy", fmt.Errorf("policy failure")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyUnsealError(tc.raw, true)
			if !errors.Is(err, ErrPolicyFailed) {
				t.Errorf("expected ErrPolicyFailed for pcrlock, got: %v", err)
			}
			if errors.Is(err, ErrWrongPIN) {
				t.Error("pcrlock failure must not leak ErrWrongPIN (error oracle)")
			}
			if errors.Is(err, ErrPCRMismatch) {
				t.Error("pcrlock failure must not leak ErrPCRMismatch (error oracle)")
			}
		})
	}
}

// TestPCRLockUnsealLockoutNotCollapsed pins that a TPM lockout keeps its
// own classification — the caller needs it to decide whether retrying is
// pointless.
func TestPCRLockUnsealLockoutNotCollapsed(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("TPM_RC_LOCKOUT"), true)
	if !errors.Is(err, ErrTPMLockout) {
		t.Errorf("expected ErrTPMLockout, got: %v", err)
	}
	if errors.Is(err, ErrPolicyFailed) {
		t.Error("lockout must not be collapsed into ErrPolicyFailed")
	}
}

// TestPCRLockUnsealErrorIsRetryable documents the initrd-side contract
// that the classification must satisfy: a pcrlock policy failure is
// retryable, so the user gets another PIN prompt.
func TestPCRLockUnsealErrorIsRetryable(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("TPM_RC_AUTH_FAIL"), true)
	// The initrd retries on ErrWrongPIN or ErrPolicyFailed.
	retryable := errors.Is(err, ErrWrongPIN) || errors.Is(err, ErrPolicyFailed)
	if !retryable {
		t.Errorf("pcrlock failure is not retryable — the user would get no second PIN prompt: %v", err)
	}
}
