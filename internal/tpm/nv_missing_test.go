package tpm

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// TestIsNVIndexMissing pins the classification that decides whether the user
// is told to re-enroll a token. Only TPM_RC_HANDLE means "the index is not
// defined"; every other failure is potentially transient.
func TestIsNVIndexMissing(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"undefined index", tpm2.TPMRCHandle, true},
		{"undefined index with handle index bits", tpm2.TPMRCHandle + 0x100, true},
		{"index already defined", tpm2.TPMRCNVDefined, false},
		{"policy failure", tpm2.TPMRCPolicyFail, false},
		{"lockout", tpm2.TPMRCLockout, false},
		{"not a TPM error", errors.New("connection refused"), false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNVIndexMissing(tc.err); got != tc.want {
				t.Errorf("IsNVIndexMissing(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
