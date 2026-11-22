package main

import (
	"encoding/base64"
	"testing"

	"github.com/zaolin/vanguard/internal/pcrlock"
)

// TestTokenNVStatus pins that verification uses the NV binding, not just the
// index number: an index redefined at the same handle leaves the number
// unchanged but makes the token unusable.
func TestTokenNVStatus(t *testing.T) {
	blobA := base64.StdEncoding.EncodeToString([]byte{0x01})
	blobB := base64.StdEncoding.EncodeToString([]byte{0x02})

	tests := []struct {
		name        string
		token       *pcrlock.LUKSTPMToken
		policy      *pcrlock.Policy
		wantStatus  string
		wantMatches bool
	}{
		{
			name:        "same index and same blob match",
			token:       &pcrlock.LUKSTPMToken{NVIndex: 1, NVHandle: blobA, HasPCRLock: true},
			policy:      &pcrlock.Policy{NVIndex: 1, NVHandle: blobA},
			wantStatus:  "match",
			wantMatches: true,
		},
		{
			name:        "same index but a different blob is stale",
			token:       &pcrlock.LUKSTPMToken{NVIndex: 1, NVHandle: blobA, HasPCRLock: true},
			policy:      &pcrlock.Policy{NVIndex: 1, NVHandle: blobB},
			wantStatus:  "stale",
			wantMatches: false,
		},
		{
			name:        "a classic token is not pcrlock-bound",
			token:       &pcrlock.LUKSTPMToken{NVIndex: 0},
			policy:      &pcrlock.Policy{NVIndex: 1, NVHandle: blobA},
			wantStatus:  "not-pcrlock-bound",
			wantMatches: true,
		},
		{
			name:        "pcrlock declared without a blob is unknown",
			token:       &pcrlock.LUKSTPMToken{HasPCRLock: true},
			policy:      &pcrlock.Policy{NVIndex: 1, NVHandle: blobA},
			wantStatus:  "unknown",
			wantMatches: false,
		},
		{
			name:        "a hybrid PCR and pcrlock token is unknown",
			token:       &pcrlock.LUKSTPMToken{NVHandle: blobA, HasPCRLock: true, PCRs: []int{7}},
			policy:      &pcrlock.Policy{NVIndex: 1, NVHandle: blobA},
			wantStatus:  "unknown",
			wantMatches: false,
		},
		{
			name:        "a policy without nvHandle is unknown",
			token:       &pcrlock.LUKSTPMToken{NVHandle: blobA, HasPCRLock: true},
			policy:      &pcrlock.Policy{NVIndex: 1},
			wantStatus:  "unknown",
			wantMatches: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _, matches := tokenNVStatus(tc.token, tc.policy)
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
			if matches != tc.wantMatches {
				t.Errorf("matches = %v, want %v", matches, tc.wantMatches)
			}
		})
	}
}
