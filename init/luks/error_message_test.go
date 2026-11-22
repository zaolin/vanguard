package luks

import (
	"errors"
	"fmt"
	"testing"

	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// TestFormatTPMErrorSurfacesStaleNVIndex pins that the actionable
// "re-enroll the token" message reaches the user.
//
// The stale-index error deliberately does NOT wrap ErrPolicyFailed, so
// the generic "TPM unlock failed" mapping cannot swallow the
// remediation. This is a regression test: when the error wrapped
// ErrPolicyFailed, the re-enroll instruction was silently discarded and
// the user got no explanation for a boot that suddenly required HOTP
// recovery.
func TestFormatTPMErrorSurfacesStaleNVIndex(t *testing.T) {
	err := fmt.Errorf("%w: index 0x195cd64 is missing from the TPM (the policy was regenerated at a different index) — re-enroll the token: vanguard enroll -u <uki> -l <device>",
		intpm.ErrTokenStaleNVIndex)

	got := formatTPMError(err)
	if got == "TPM unlock failed" {
		t.Fatalf("actionable message collapsed to the generic one: %q", got)
	}
	for _, want := range []string{"re-enroll", "0x195cd64", "vanguard enroll"} {
		if !contains(got, want) {
			t.Errorf("message %q missing %q", got, want)
		}
	}
}

// TestFormatTPMErrorStillCollapsesPolicyFailures keeps the error-oracle
// protection intact: a plain policy failure must still be collapsed to
// the generic message (so an attacker cannot distinguish a wrong PIN from
// a wrong PCR value).
func TestFormatTPMErrorStillCollapsesPolicyFailures(t *testing.T) {
	err := fmt.Errorf("%w: some internal detail", intpm.ErrPolicyFailed)
	if got := formatTPMError(err); got != "TPM unlock failed" {
		t.Errorf("formatTPMError = %q, want %q (error-oracle protection)", got, "TPM unlock failed")
	}
}

// TestFormatTPMErrorStaleIndexNotTreatedAsPolicyFailure verifies the
// sentinel does not accidentally satisfy the ErrPolicyFailed check (which
// would make the generic mapping win by accident in the future).
func TestFormatTPMErrorStaleIndexNotTreatedAsPolicyFailure(t *testing.T) {
	if errors.Is(intpm.ErrTokenStaleNVIndex, intpm.ErrPolicyFailed) {
		t.Error("ErrTokenStaleNVIndex must not wrap ErrPolicyFailed")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
