package luks

import (
	"encoding/json"
	"testing"
)

// TestTokensAreOrderedByID pins deterministic token ordering.
//
// The LUKS2 metadata stores tokens in a map, and Go randomizes map
// iteration order. Unordered tokens made the token selection vary between
// boots (which token is tried first at unlock, which one `vanguard status`
// reports) — a classic source of "sometimes it behaves differently".
func TestTokensAreOrderedByID(t *testing.T) {
	d := &deviceV2{meta: &metadata{
		Tokens: map[int]json.RawMessage{
			0: json.RawMessage(`{"type":"systemd-tpm2","keyslots":[0]}`),
			1: json.RawMessage(`{"type":"systemd-tpm2","keyslots":[1]}`),
			2: json.RawMessage(`{"type":"password","keyslots":[2]}`),
			3: json.RawMessage(`{"type":"systemd-tpm2","keyslots":[3]}`),
		},
	}}

	// Run repeatedly: the order must never change.
	for run := 0; run < 50; run++ {
		tokens, err := d.Tokens()
		if err != nil {
			t.Fatalf("Tokens: %v", err)
		}
		if len(tokens) != 4 {
			t.Fatalf("got %d tokens, want 4", len(tokens))
		}
		for i, tok := range tokens {
			if tok.ID != i {
				t.Fatalf("run %d: token at position %d has ID %d — order is not sorted by ID", run, i, tok.ID)
			}
		}
	}
}

// TestTokensOrderStableAcrossInstances ensures the order is a property of
// the data, not of a particular map instance.
func TestTokensOrderStableAcrossInstances(t *testing.T) {
	build := func() *deviceV2 {
		return &deviceV2{meta: &metadata{
			Tokens: map[int]json.RawMessage{
				7: json.RawMessage(`{"type":"systemd-tpm2","keyslots":[0]}`),
				2: json.RawMessage(`{"type":"systemd-tpm2","keyslots":[1]}`),
				5: json.RawMessage(`{"type":"systemd-tpm2","keyslots":[2]}`),
			},
		}}
	}

	want := []int{2, 5, 7}
	for run := 0; run < 50; run++ {
		tokens, err := build().Tokens()
		if err != nil {
			t.Fatalf("Tokens: %v", err)
		}
		for i, tok := range tokens {
			if tok.ID != want[i] {
				t.Fatalf("run %d: position %d has ID %d, want %d", run, i, tok.ID, want[i])
			}
		}
	}
}
