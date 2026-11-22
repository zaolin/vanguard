package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/zaolin/vanguard/internal/tpm"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestCollectTPMStatusAgainstSimulator exercises the real collection path:
// identity, banks, RNG and the seal/unseal roundtrip must all succeed against
// the simulator.
func TestCollectTPMStatusAgainstSimulator(t *testing.T) {
	swtpmtest.SetupEnvTransport(t)

	data := &statusData{}
	collectTPMStatus(data)

	if data.TPM.Identity == nil {
		t.Fatalf("no identity collected: %s", data.TPM.IdentityError)
	}
	if len(data.TPM.Banks) == 0 {
		t.Errorf("no PCR banks collected: %s", data.TPM.BanksError)
	}
	if data.TPM.RandomOK == nil || !*data.TPM.RandomOK {
		t.Errorf("the RNG check did not succeed: %s", data.TPM.RandomError)
	}
	if data.TPM.RoundtripOK == nil || !*data.TPM.RoundtripOK {
		t.Errorf("the roundtrip did not succeed: %s", data.TPM.RoundtripError)
	}
	if data.TPM.RoundtripSkipped != "" {
		t.Errorf("the roundtrip was skipped against a healthy simulator: %s", data.TPM.RoundtripSkipped)
	}
}

// TestCollectTPMStatusClassifiesRoundtripFailure pins the production wiring:
// a genuine seal/unseal mismatch must be classified as "failed", not
// "unverified" — otherwise a broken TPM would only produce a warning.
func TestCollectTPMStatusClassifiesRoundtripFailure(t *testing.T) {
	swtpmtest.SetupEnvTransport(t)

	orig := sealRoundtrip
	t.Cleanup(func() { sealRoundtrip = orig })
	sealRoundtrip = func(*tpm.Client) error { return tpm.ErrRoundtripMismatch }

	data := &statusData{}
	collectTPMStatus(data)

	if data.TPM.RoundtripClass != "failed" {
		t.Errorf("RoundtripClass = %q, want failed for a genuine mismatch", data.TPM.RoundtripClass)
	}
}

// TestAuthBlockReason pins the fail-safe gating for every state in which an
// authorization could fail — including the selective failure where the
// permanent-flags read fails although the lockout read succeeded.
func TestAuthBlockReason(t *testing.T) {
	tests := []struct {
		name       string
		lockoutErr string
		inLockout  bool
		flags      tpm.PermanentFlags
		flagsErr   error
		wantBlock  bool
	}{
		{name: "healthy", wantBlock: false},
		{name: "lockout read failed", lockoutErr: "io", wantBlock: true},
		{name: "in lockout", inLockout: true, wantBlock: true},
		{name: "owner auth set", flags: tpm.PermanentOwnerAuthSet, wantBlock: true},
		{name: "lockout auth set", flags: tpm.PermanentLockoutAuthSet, wantBlock: true},
		{name: "permanent-flags read failed although the lockout read succeeded", flagsErr: errors.New("io"), wantBlock: true},
		{name: "in lockout wins over flags", inLockout: true, flagsErr: errors.New("io"), wantBlock: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := authBlockReason(tc.lockoutErr, tc.inLockout, tc.flags, tc.flagsErr)
			if tc.wantBlock && got == "" {
				t.Error("expected the operation to be blocked (fail-safe)")
			}
			if !tc.wantBlock && got != "" {
				t.Errorf("unexpected block: %q", got)
			}
		})
	}
}

// TestAllUnknownPCRsDoNotClaimUnenforced pins that unreadable PCRs are not
// misreported as "no PCRs enforced" when the policy does enforce them.
func TestAllUnknownPCRsDoNotClaimUnenforced(t *testing.T) {
	data := &statusData{}
	data.PCRLock = &pcrlockInfo{
		PolicyPath: "/boot/policy.json",
		PCRResults: []pcrStatus{
			{PCR: 4, Name: "boot-loader", IsEnforced: true, Unknown: true},
			{PCR: 7, Name: "secure-boot", IsEnforced: true, Unknown: true},
		},
	}

	v := buildBootChainTamperingVector(data)

	for _, m := range v.Mitigations {
		if strings.Contains(m.Detail, "no PCRs enforced") {
			t.Errorf("unknown PCRs were misreported as unenforced: %+v", m)
		}
		if m.Name == "PCRLock PCR binding" && m.Status == "ok" {
			t.Errorf("an all-unknown result was reported as all-match: %+v", m)
		}
	}
}
