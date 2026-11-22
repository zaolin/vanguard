package pcrlock

import (
	"encoding/json"
	"errors"
	"testing"
)

// dumpJSON builds a cryptsetup luksDump JSON metadata document with the given
// token payloads keyed by token ID.
func dumpJSON(t *testing.T, tokens map[string]map[string]interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{"tokens": tokens})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// withLuksDump feeds a fixed luksDump document to the production token lookup.
func withLuksDump(t *testing.T, output []byte, err error) {
	t.Helper()
	orig := luksDumpRunner
	luksDumpRunner = func(string) ([]byte, error) { return output, err }
	t.Cleanup(func() { luksDumpRunner = orig })
}

// TestGetLUKSTPMTokenReturnsPcrlockToken pins the happy path of the production
// lookup: a pcrlock token must be found, with its NV index parsed from the
// ESYS_TR blob and the blob itself preserved for the staleness comparison.
func TestGetLUKSTPMTokenReturnsPcrlockToken(t *testing.T) {
	blob := encodeTestBlob(buildTestESYSBlob(0x01919ea9, 0x01))
	dump := dumpJSON(t, map[string]map[string]interface{}{
		"0": {
			"type":            "systemd-tpm2",
			"tpm2_pcrlock":    true,
			"tpm2_pcrlock_nv": blob,
			"tpm2-pin":        true,
		},
	})
	withLuksDump(t, dump, nil)

	token, err := GetLUKSTPMToken("/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("GetLUKSTPMToken: %v", err)
	}
	if token == nil {
		t.Fatal("no token returned")
	}
	if !token.HasPCRLock {
		t.Error("HasPCRLock = false, want true")
	}
	if token.NVIndex != 0x01919ea9 {
		t.Errorf("NVIndex = 0x%x, want 0x01919ea9", token.NVIndex)
	}
	if token.NVHandle != blob {
		t.Error("the NV handle blob was not preserved")
	}
	if !token.HasPIN {
		t.Error("HasPIN = false, want true")
	}
}

// TestGetLUKSTPMTokenClassicToken pins that a classic PCR-bound token is
// returned as such, not reported as missing.
func TestGetLUKSTPMTokenClassicToken(t *testing.T) {
	dump := dumpJSON(t, map[string]map[string]interface{}{
		"0": {"type": "systemd-tpm2", "tpm2-pcrs": []int{7}},
	})
	withLuksDump(t, dump, nil)

	token, err := GetLUKSTPMToken("/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("GetLUKSTPMToken: %v", err)
	}
	if token.HasPCRLock {
		t.Error("a classic token must not be marked pcrlock-bound")
	}
	if token.NVHandle != "" {
		t.Error("a classic token must not carry an NV handle")
	}
	if len(token.PCRs) != 1 || token.PCRs[0] != 7 {
		t.Errorf("PCRs = %v, want [7]", token.PCRs)
	}
}

// TestGetLUKSTPMTokenNoToken pins the sentinel used to distinguish "nothing
// enrolled" from a failed lookup.
func TestGetLUKSTPMTokenNoToken(t *testing.T) {
	withLuksDump(t, dumpJSON(t, map[string]map[string]interface{}{}), nil)

	_, err := GetLUKSTPMToken("/dev/nvme0n1p2")
	if !errors.Is(err, ErrNoTPMToken) {
		t.Errorf("err = %v, want ErrNoTPMToken", err)
	}
}

// TestGetLUKSTPMTokenCorruptSystemdTokenWinsOverClassic pins that a corrupt
// systemd-tpm2 token is reported even when another, well-formed classic token
// exists — otherwise the device's pcrlock state would look decidable while it
// is not.
func TestGetLUKSTPMTokenCorruptSystemdTokenWinsOverClassic(t *testing.T) {
	dump := dumpJSON(t, map[string]map[string]interface{}{
		"0": {"type": "systemd-tpm2", "tpm2-pcrs": "not-an-array"}, // undecodable
		"1": {"type": "systemd-tpm2", "tpm2-pcrs": []int{7}},
	})
	withLuksDump(t, dump, nil)

	_, err := GetLUKSTPMToken("/dev/nvme0n1p2")
	if err == nil {
		t.Fatal("expected a decode error")
	}
	if errors.Is(err, ErrNoTPMToken) {
		t.Error("a corrupt token must not be reported as 'no token'")
	}
}

// TestGetLUKSTPMTokenIgnoresOtherTokenTypes pins that an unrelated token type
// (e.g. fido2) neither satisfies the lookup nor fails it.
func TestGetLUKSTPMTokenIgnoresOtherTokenTypes(t *testing.T) {
	dump := dumpJSON(t, map[string]map[string]interface{}{
		"0": {"type": "systemd-fido2", "something": []string{"x"}},
		"1": {"type": "systemd-tpm2", "tpm2-pcrs": []int{7}},
	})
	withLuksDump(t, dump, nil)

	token, err := GetLUKSTPMToken("/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("GetLUKSTPMToken: %v", err)
	}
	if token.Type != "systemd-tpm2" {
		t.Errorf("type = %q, want systemd-tpm2", token.Type)
	}
}

// TestGetLUKSTPMTokenDeterministicOrder pins that the lowest token ID wins
// regardless of the map iteration order — and that the ordering is NUMERIC,
// not lexicographic: token 2 must be selected before token 10, otherwise a
// classic token could be preferred over the pcrlock one.
func TestGetLUKSTPMTokenDeterministicOrder(t *testing.T) {
	first := encodeTestBlob(buildTestESYSBlob(0x01919ea9, 0x01))
	second := encodeTestBlob(buildTestESYSBlob(0x0195cd64, 0x02))
	dump := dumpJSON(t, map[string]map[string]interface{}{
		"10": {"type": "systemd-tpm2", "tpm2_pcrlock": true, "tpm2_pcrlock_nv": second},
		"2":  {"type": "systemd-tpm2", "tpm2_pcrlock": true, "tpm2_pcrlock_nv": first},
	})
	withLuksDump(t, dump, nil)

	for i := 0; i < 20; i++ {
		token, err := GetLUKSTPMToken("/dev/nvme0n1p2")
		if err != nil {
			t.Fatalf("GetLUKSTPMToken: %v", err)
		}
		if token.NVIndex != 0x01919ea9 {
			t.Fatalf("run %d: NVIndex = 0x%x, want token 2 (numeric order), not token 10", i, token.NVIndex)
		}
	}
}

// TestGetLUKSTPMTokenDumpFailure pins that a failed cryptsetup call is an
// operational error, never "no token".
func TestGetLUKSTPMTokenDumpFailure(t *testing.T) {
	withLuksDump(t, nil, errors.New("i/o error"))

	_, err := GetLUKSTPMToken("/dev/nvme0n1p2")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrNoTPMToken) {
		t.Error("a failed luksDump must not be reported as 'no token'")
	}
}
