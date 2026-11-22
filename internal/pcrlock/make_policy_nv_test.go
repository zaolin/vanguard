package pcrlock

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicyFile writes a minimal policy JSON with the given nvIndex.
func writePolicyFile(t *testing.T, dir, name string, nvIndex int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := map[string]interface{}{"pcrBank": "sha256", "pcrValues": []interface{}{}, "nvIndex": nvIndex}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// withTokenGetter swaps the injectable token getter for the test duration.
func withTokenGetter(t *testing.T, token *LUKSTPMToken, err error) {
	t.Helper()
	orig := getLUKSTokenForReuse
	getLUKSTokenForReuse = func(string) (*LUKSTPMToken, error) { return token, err }
	t.Cleanup(func() { getLUKSTokenForReuse = orig })
}

// TestResolveReuseNVIndex_PolicyFileWins pins source priority: the policy
// file's nvIndex is used even when the LUKS token pins a different one.
func TestResolveReuseNVIndex_PolicyFileWins(t *testing.T) {
	dir := t.TempDir()
	path := writePolicyFile(t, dir, "kernel.pcrlock.json", 0x1919ea9)
	withTokenGetter(t, &LUKSTPMToken{Type: "systemd-tpm2", NVIndex: 0x195cd64, HasPCRLock: true}, nil)

	idx, err := resolveReuseNVIndex(path, "/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("resolveReuseNVIndex: %v", err)
	}
	if idx != 0x1919ea9 {
		t.Errorf("idx = 0x%x, want 0x1919ea9 (policy file must win)", idx)
	}
}

// TestResolveReuseNVIndex_TokenPinFallback is the regression test for the
// "Token NV mismatch" race: when the policy file is missing (a previous
// make-policy run was interrupted after the file was deleted), the token's
// pinned index keeps the reuse alive instead of allocating a fresh one
// that orphans the token.
func TestResolveReuseNVIndex_TokenPinFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel.pcrlock.json") // absent
	withTokenGetter(t, &LUKSTPMToken{Type: "systemd-tpm2", NVIndex: 0x195cd64, HasPCRLock: true}, nil)

	idx, err := resolveReuseNVIndex(path, "/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("resolveReuseNVIndex: %v", err)
	}
	if idx != 0x195cd64 {
		t.Errorf("idx = 0x%x, want 0x195cd64 (token pin fallback)", idx)
	}
}

// TestResolveReuseNVIndex_RefusesToOrphanPcrlockToken pins the refusal:
// no index source + existing pcrlock token → error with re-enroll guidance,
// never a silent fresh allocation.
func TestResolveReuseNVIndex_RefusesToOrphanPcrlockToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel.pcrlock.json") // absent
	withTokenGetter(t, &LUKSTPMToken{Type: "systemd-tpm2", NVIndex: 0, HasPCRLock: true}, nil)

	idx, err := resolveReuseNVIndex(path, "/dev/nvme0n1p2")
	if err == nil {
		t.Fatal("expected refusal error, got nil")
	}
	if idx != 0 {
		t.Errorf("idx = 0x%x, want 0 on refusal", idx)
	}
	// Guidance must mention the actual commands
	for _, want := range []string{"systemd-cryptenroll", "nvIndex"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing guidance substring %q", err.Error(), want)
		}
	}
}

// TestResolveReuseNVIndex_FreshAllocWhenNoToken: no LUKS device (initial
// enrollment) → zero index, no error.
func TestResolveReuseNVIndex_FreshAllocWhenNoToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel.pcrlock.json") // absent

	idx, err := resolveReuseNVIndex(path, "")
	if err != nil {
		t.Fatalf("resolveReuseNVIndex: %v", err)
	}
	if idx != 0 {
		t.Errorf("idx = 0x%x, want 0 for fresh allocation", idx)
	}
}

// TestResolveReuseNVIndex_NoTokenProceeds: a device with no systemd-tpm2
// token at all is the initial-enrollment case, so fresh allocation is right.
func TestResolveReuseNVIndex_NoTokenProceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel.pcrlock.json") // absent
	withTokenGetter(t, nil, ErrNoTPMToken)

	idx, err := resolveReuseNVIndex(path, "/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("resolveReuseNVIndex: %v", err)
	}
	if idx != 0 {
		t.Errorf("idx = 0x%x, want 0 for fresh allocation", idx)
	}
}

// TestResolveReuseNVIndex_LookupFailureRefuses: a failed token lookup must
// not be read as "nothing enrolled". Allocating a fresh index while a token
// may exist would orphan it and break the next boot.
func TestResolveReuseNVIndex_LookupFailureRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel.pcrlock.json") // absent
	withTokenGetter(t, nil, errors.New("cryptsetup: i/o error"))

	idx, err := resolveReuseNVIndex(path, "/dev/nvme0n1p2")
	if err == nil {
		t.Fatal("expected a refusal when the token lookup fails")
	}
	if idx != 0 {
		t.Errorf("idx = 0x%x, want 0 on refusal", idx)
	}
	if !strings.Contains(err.Error(), "token state is unknown") {
		t.Errorf("error %q does not explain the refusal", err)
	}
}

// TestResolveReuseNVIndex_NonPcrlockTokenProceeds: a classic (non-pcrlock)
// token pins no pcrlock index, so a fresh allocation cannot orphan it.
func TestResolveReuseNVIndex_NonPcrlockTokenProceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel.pcrlock.json") // absent
	withTokenGetter(t, &LUKSTPMToken{Type: "systemd-tpm2", NVIndex: 0, HasPCRLock: false}, nil)

	idx, err := resolveReuseNVIndex(path, "/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("resolveReuseNVIndex: %v", err)
	}
	if idx != 0 {
		t.Errorf("idx = 0x%x, want 0 (fresh allocation is safe for non-pcrlock tokens)", idx)
	}
}
