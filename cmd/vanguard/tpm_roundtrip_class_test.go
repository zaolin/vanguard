package main

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm"
)

// TestRoundtripClassFor pins the error classification: a genuine seal/unseal
// failure is critical, an authorization or transport problem is only
// "unverified" — never a false "the TPM cannot protect the key".
func TestRoundtripClassFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "a data mismatch is a genuine failure", err: tpm.ErrRoundtripMismatch, want: "failed"},
		{name: "a TPM error response is a genuine failure", err: tpm2.TPMRCPolicyFail, want: "failed"},
		{name: "an authorization failure is unverified", err: tpm2.TPMRCAuthFail, want: "unverified"},
		{name: "a transport failure is unverified", err: errors.New("dial unix: connection refused"), want: "unverified"},
		{name: "a random local error is unverified", err: errors.New("some local error"), want: "unverified"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := roundtripClassFor(tc.err); got != tc.want {
				t.Errorf("class = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPCRBanksPaginatedIsNotMissingBank pins that a paginated capability
// response is reported as an enumeration problem rather than as "no SHA-256
// bank" — a false critical on a healthy TPM.
func TestPCRBanksPaginatedIsNotMissingBank(t *testing.T) {
	client := tpm.NewWithTransport(fakeMoreDataTransport{})

	_, err := client.PCRBanks()
	if err == nil {
		t.Fatal("expected an error for a paginated response")
	}
	if got := err.Error(); !containsStr(got, "paginated") {
		t.Errorf("error %q does not mention pagination", got)
	}
}

// fakeMoreDataTransport returns a GetCapability response with MoreData set,
// so the pagination branch can be exercised without a TPM.
type fakeMoreDataTransport struct{}

func (fakeMoreDataTransport) Send([]byte) ([]byte, error) {
	// tag(2) size(4) rc(4) moreData(1) capability(4) selectionCount(4).
	out := make([]byte, 19)
	out[0] = 0x80
	out[1] = 0x01
	out[5] = byte(len(out))
	out[10] = 1 // MoreData = YES
	// capability = TPM_CAP_PCRS (0) and count = 0, both already zero.
	return out, nil
}

func (fakeMoreDataTransport) Close() error { return nil }
