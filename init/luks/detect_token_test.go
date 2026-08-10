package luks

import (
	"encoding/base64"
	"testing"
)

// --- Tests for parseTokenJSON ---

func TestParseTokenJSON_PcrlockV255(t *testing.T) {
	// systemd v255+ format with underscore variants
	nvData := make([]byte, 16)
	nvData[0], nvData[1] = 14, 0
	nvData[2], nvData[3], nvData[4], nvData[5] = 0x01, 0x80, 0x00, 0x01
	nvData[6], nvData[7] = 0x00, 0x0B
	nvData[14], nvData[15] = 0, 34

	tokenJSON := map[string]interface{}{
		"tpm2-blob":       base64.StdEncoding.EncodeToString([]byte("test-blob")),
		"tpm2-pcr-bank":   "sha256",
		"tpm2-pin":        true,
		"tpm2_pcrlock":    true,
		"tpm2_pcrlock_nv": base64.StdEncoding.EncodeToString(nvData),
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	if !token.UsePCRLock {
		t.Error("expected UsePCRLock=true for pcrlock token")
	}

	if token.PCRLockNV != 0x01800001 {
		t.Errorf("PCRLockNV = 0x%x, want 0x01800001", token.PCRLockNV)
	}

	if !token.NeedsPIN {
		t.Error("expected NeedsPIN=true")
	}

	if token.PCRBank != "sha256" {
		t.Errorf("PCRBank = %q, want sha256", token.PCRBank)
	}
}

func TestParseTokenJSON_LegacyHyphen(t *testing.T) {
	// Legacy format with hyphen variants
	tokenJSON := map[string]interface{}{
		"tpm2-blob":       base64.StdEncoding.EncodeToString([]byte("test-blob")),
		"tpm2-pcrs":       []interface{}{float64(7), float64(11)},
		"tpm2-pcr-bank":   "sha256",
		"tpm2-pin":        false,
		"tpm2-pcrlock":    true,
		"tpm2-pcrlock-nv": float64(0x01800001),
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	if !token.UsePCRLock {
		t.Error("expected UsePCRLock=true")
	}

	if token.PCRLockNV != 0x01800001 {
		t.Errorf("PCRLockNV = 0x%x, want 0x01800001", token.PCRLockNV)
	}

	if len(token.PCRs) != 2 {
		t.Fatalf("expected 2 PCRs, got %d", len(token.PCRs))
	}

	if token.PCRs[0] != 7 || token.PCRs[1] != 11 {
		t.Errorf("PCRs = %v, want [7, 11]", token.PCRs)
	}
}

func TestParseTokenJSON_PinOnly(t *testing.T) {
	// PIN-only token: no PCRs, no pcrlock
	tokenJSON := map[string]interface{}{
		"tpm2-blob": base64.StdEncoding.EncodeToString([]byte("test-blob")),
		"tpm2-pin":  true,
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	if token.UsePCRLock {
		t.Error("expected UsePCRLock=false for PIN-only token")
	}

	if !token.NeedsPIN {
		t.Error("expected NeedsPIN=true")
	}

	if len(token.PCRs) != 0 {
		t.Errorf("expected 0 PCRs for PIN-only, got %d", len(token.PCRs))
	}

	if token.PCRLockNV != 0 {
		t.Errorf("expected PCRLockNV=0, got 0x%x", token.PCRLockNV)
	}
}

func TestParseTokenJSON_MissingBank(t *testing.T) {
	// parseTokenJSON (detect.go) does NOT set a default bank — it returns
	// whatever is in the JSON, empty if absent. ParseTPM2Token (token.go)
	// sets the default "sha256".
	tokenJSON := map[string]interface{}{
		"tpm2-blob": base64.StdEncoding.EncodeToString([]byte("x")),
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	// detect.go's parseTokenJSON leaves PCRBank empty when not specified
	if token.PCRBank != "" {
		t.Errorf("PCRBank = %q, want empty (detect.go doesn't set default)", token.PCRBank)
	}
}

func TestParseTokenJSON_MissingPrimaryAlg(t *testing.T) {
	// parseTokenJSON (detect.go) does NOT set a default primary alg
	tokenJSON := map[string]interface{}{
		"tpm2-blob": base64.StdEncoding.EncodeToString([]byte("x")),
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	if token.PrimaryAlg != "" {
		t.Errorf("PrimaryAlg = %q, want empty (detect.go doesn't set default)", token.PrimaryAlg)
	}
}

func TestParseTokenJSON_SaltUnderscore(t *testing.T) {
	// tpm2_salt (underscore) variant should be used when tpm2-salt is absent
	saltData := []byte{0x01, 0x02, 0x03, 0x04}
	tokenJSON := map[string]interface{}{
		"tpm2-blob": base64.StdEncoding.EncodeToString([]byte("x")),
		"tpm2_salt": base64.StdEncoding.EncodeToString(saltData),
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	if len(token.Salt) != len(saltData) {
		t.Errorf("Salt length = %d, want %d", len(token.Salt), len(saltData))
	}
}

func TestParseTokenJSON_MissingBlob(t *testing.T) {
	// Missing blob should produce a token with empty Blob (not an error)
	tokenJSON := map[string]interface{}{
		"tpm2-pin": true,
	}

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		t.Fatalf("parseTokenJSON: %v", err)
	}

	if len(token.Blob) != 0 {
		t.Errorf("expected empty blob, got %d bytes", len(token.Blob))
	}
}

// --- Tests for parseNVIndexFromPublic (already in detect_test.go, but add edge cases) ---

func TestParseNVIndexFromPublic_BothStrategiesFail(t *testing.T) {
	// Data that doesn't look like a valid NV index at any offset
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	got := parseNVIndexFromPublic(data)
	if got != 0 {
		t.Errorf("expected 0 for all-zeros data, got 0x%x", got)
	}
}

func TestParseNVIndexFromPublic_PreferSpecCompliant(t *testing.T) {
	// When offset 2 has a valid NV index, it should be preferred over offset 0
	// even if offset 0 also looks valid
	data := make([]byte, 8)
	// Offset 0: 0x01800001 (valid)
	data[0], data[1], data[2], data[3] = 0x01, 0x80, 0x00, 0x01
	// Offset 2: 0x01800002 (valid, different)
	data[2], data[3], data[4], data[5] = 0x01, 0x80, 0x00, 0x02

	got := parseNVIndexFromPublic(data)
	if got != 0x01800002 {
		t.Errorf("expected 0x01800002 (offset 2, spec-compliant), got 0x%x", got)
	}
}
