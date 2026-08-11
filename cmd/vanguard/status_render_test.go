package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHexDecode(t *testing.T) {
	got, err := hexDecode("deadbeef")
	if err != nil {
		t.Fatalf("hexDecode: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("length: got %d, want 4", len(got))
	}
	if got[0] != 0xde {
		t.Errorf("byte[0]: got %x, want de", got[0])
	}
}

func TestHexDecodeInvalid(t *testing.T) {
	_, err := hexDecode("zzzz")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestHexEncode(t *testing.T) {
	input := []byte{0xde, 0xad, 0xbe, 0xef}
	got := hexEncode(input)
	if got != "deadbeef" {
		t.Errorf("hexEncode: got %s, want deadbeef", got)
	}
}

func TestRenderTier(t *testing.T) {
	tiers := []string{"PHYSICAL", "HIGH", "WARNING", "CRITICAL", "LOW", "UNKNOWN"}
	for _, tier := range tiers {
		result := renderTier(tier)
		if !strings.Contains(result, "PROTECTION TIER") {
			t.Errorf("renderTier(%s): missing 'PROTECTION TIER'", tier)
		}
		if !strings.Contains(result, tier) {
			t.Errorf("renderTier(%s): missing tier label", tier)
		}
	}
}

func TestRenderMitigation(t *testing.T) {
	tests := []struct {
		name   string
		status string
		detail string
	}{
		{"Secure Boot", "ok", "enabled"},
		{"dbx", "warning", "not configured"},
		{"Debug", "critical", "not locked"},
		{"Unknown", "info", "not checked"},
	}
	for _, tt := range tests {
		m := mitigation{Name: tt.name, Status: tt.status, Detail: tt.detail}
		result := renderMitigation(&m)
		if !strings.Contains(result, tt.name) {
			t.Errorf("renderMitigation(%s): missing name %s", tt.status, tt.name)
		}
		if !strings.Contains(result, tt.detail) {
			t.Errorf("renderMitigation(%s): missing detail %s", tt.status, tt.detail)
		}
	}
}

func TestRenderMitigationWithFix(t *testing.T) {
	m := mitigation{Name: "Test", Status: "warning", Detail: "problem", Fix: "run fix"}
	result := renderMitigation(&m)
	if !strings.Contains(result, "run fix") {
		t.Error("renderMitigation: missing fix text")
	}
}

func TestParseTokenDetailValid(t *testing.T) {
	payload := `{"tpm2-pin": true, "tpm2-pcrlock": true, "tpm2-salt": "abc", "tpm2-srk": 12345}`
	td := parseTokenDetail([]byte(payload))
	if !td.HasPIN {
		t.Error("HasPIN: expected true")
	}
	if !td.HasPCRLock {
		t.Error("HasPCRLock: expected true")
	}
	if !td.HasSalt {
		t.Error("HasSalt: expected true")
	}
	if !td.HasSRK {
		t.Error("HasSRK: expected true")
	}
	if td.PCRBank != "sha256" {
		t.Errorf("PCRBank: got %s, want sha256", td.PCRBank)
	}
}

func TestParseTokenDetailEmpty(t *testing.T) {
	td := parseTokenDetail([]byte("invalid json"))
	if td.HasPIN || td.HasPCRLock || td.HasSRK || td.HasSalt {
		t.Error("expected all false for invalid JSON")
	}
	if td.PCRBank != "sha256" {
		t.Errorf("PCRBank: got %s, want sha256 (default)", td.PCRBank)
	}
}

func TestParseTokenDetailWithPCRLockNV(t *testing.T) {
	// Test with numeric NV index
	payload := `{"tpm2-pcrlock": true, "tpm2-pcrlock-nv": 27701248}`
	td := parseTokenDetail([]byte(payload))
	if !td.HasPCRLock {
		t.Error("HasPCRLock: expected true")
	}
	if td.NVIndex != 27701248 {
		t.Errorf("NVIndex: got %d, want 27701248", td.NVIndex)
	}
}

func TestParseTokenDetailWithPCRLockNVAlt(t *testing.T) {
	// Test with base64-encoded NV public (alternative key format)
	// Build a minimal TPM2B_NV_PUBLIC: size(2) + NVIndex(4) at offset 2
	nvBytes := make([]byte, 6)
	nvBytes[0] = 0x00 // TPM2B size high byte (will be set by actual size)
	nvBytes[1] = 0x00
	nvBytes[2] = 0x01 // NV index: 0x01C30010
	nvBytes[3] = 0xC3
	nvBytes[4] = 0x00
	nvBytes[5] = 0x10
	b64 := base64.StdEncoding.EncodeToString(nvBytes)
	payload := `{"tpm2_pcrlock_nv": "` + b64 + `"}`
	td := parseTokenDetail([]byte(payload))
	if td.NVIndex != 0x01C30010 {
		t.Errorf("NVIndex from alt: got 0x%x, want 0x01C30010", td.NVIndex)
	}
}

func TestFindPCRLockPolicy(t *testing.T) {
	// This scans /boot/EFI/*/*.pcrlock.json - may or may not find one
	result := findPCRLockPolicy()
	// Just verify it doesn't crash - result depends on system state
	_ = result
}

func TestFindPCRLockPolicyWithTempDir(t *testing.T) {
	// Create a temp file that looks like a pcrlock policy
	dir := t.TempDir()
	efiDir := filepath.Join(dir, "EFI", "Gentoo")
	os.MkdirAll(efiDir, 0755)
	policyPath := filepath.Join(efiDir, "kernel.pcrlock.json")
	os.WriteFile(policyPath, []byte("{}"), 0644)

	// findPCRLockPolicy scans /boot/EFI, not temp dirs - so this test
	// just verifies the function doesn't panic with no /boot
	_ = findPCRLockPolicy()
}

func TestRenderVectorCollapsed(t *testing.T) {
	v := &threatVector{
		Name: "Test Vector",
		Status: "ok",
		Collapsed: true,
		Mitigations: []mitigation{
			{Name: "A", Status: "ok", Detail: "active"},
			{Name: "B", Status: "ok", Detail: "enabled"},
		},
	}
	result := renderVector(v)
	if !strings.Contains(result, "Test Vector") {
		t.Error("renderVector: missing vector name")
	}
	if !strings.Contains(result, "A") {
		t.Error("renderVector: missing mitigation A")
	}
	if !strings.Contains(result, "B") {
		t.Error("renderVector: missing mitigation B")
	}
}

func TestRenderVectorExpanded(t *testing.T) {
	v := &threatVector{
		Name: "Warning Vector",
		Status: "warning",
		Collapsed: false,
		Mitigations: []mitigation{
			{Name: "A", Status: "ok", Detail: "active"},
			{Name: "B", Status: "warning", Detail: "gap", Fix: "run fix"},
		},
	}
	result := renderVector(v)
	if !strings.Contains(result, "Warning Vector") {
		t.Error("renderVector: missing vector name")
	}
	if !strings.Contains(result, "gap") {
		t.Error("renderVector: missing warning detail")
	}
	if !strings.Contains(result, "run fix") {
		t.Error("renderVector: missing fix text")
	}
}

func TestStatusJSON(t *testing.T) {
	// Verify that statusData can be marshaled to JSON
	data := statusData{
		Tier: "HIGH",
		TPM: tpmStatus{Present: true, Device: "/dev/tpmrm0"},
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(jsonData), "HIGH") {
		t.Error("JSON missing tier")
	}
	if !strings.Contains(string(jsonData), "/dev/tpmrm0") {
		t.Error("JSON missing TPM device")
	}
}

func TestVectorIsCollapsedInfo(t *testing.T) {
	v := threatVector{
		Mitigations: []mitigation{
			{Name: "A", Status: "info"},
		},
	}
	if !vectorIsCollapsed(&v) {
		t.Error("vector with only info should be collapsed")
	}
}

func TestVectorStatusEmpty(t *testing.T) {
	v := threatVector{}
	if vectorStatus(&v) != "ok" {
		t.Error("empty vector should be ok")
	}
}

func TestVectorStatusMixed(t *testing.T) {
	v := threatVector{
		Mitigations: []mitigation{
			{Status: "ok"},
			{Status: "info"},
			{Status: "warning"},
			{Status: "critical"},
		},
	}
	if vectorStatus(&v) != "critical" {
		t.Error("worst status should be critical")
	}

	v2 := threatVector{
		Mitigations: []mitigation{
			{Status: "ok"},
			{Status: "warning"},
		},
	}
	if vectorStatus(&v2) != "warning" {
		t.Error("worst status should be warning")
	}
}

