package pcrlock

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- Tests for ParsePolicy ---

func TestParsePolicy_Valid(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.pcrlock.json")

	policy := Policy{
		NVIndex: 0x01800001,
		PCRValues: []PCRValue{
			{PCR: 7, Values: []string{"abc123"}},
			{PCR: 0, Values: []string{"def456"}},
		},
	}
	data, _ := json.Marshal(policy)
	os.WriteFile(policyPath, data, 0644)

	parsed, err := ParsePolicy(policyPath)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}

	if parsed.NVIndex != 0x01800001 {
		t.Errorf("NVIndex = 0x%x, want 0x01800001", parsed.NVIndex)
	}

	if len(parsed.PCRValues) != 2 {
		t.Fatalf("expected 2 PCRValues, got %d", len(parsed.PCRValues))
	}

	if parsed.PCRValues[0].PCR != 7 {
		t.Errorf("PCRValues[0].PCR = %d, want 7", parsed.PCRValues[0].PCR)
	}
}

func TestParsePolicy_FileNotFound(t *testing.T) {
	_, err := ParsePolicy("/nonexistent/path/policy.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParsePolicy_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bad.json")
	os.WriteFile(policyPath, []byte("not json"), 0644)

	_, err := ParsePolicy(policyPath)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// --- Tests for ParsePolicyJSON ---

func TestParsePolicyJSON_ObjectFormat(t *testing.T) {
	// pcrlock.json format: {"pcrValues": [{"pcr": 7, "values": ["abc"]}, {"pcr": 0, "values": ["def"]}]}
	data := `{"pcrValues": [{"pcr": 7, "values": ["abc123"]}, {"pcr": 0, "values": ["def456"]}]}`
	info, err := ParsePolicyJSON([]byte(data))
	if err != nil {
		t.Fatalf("ParsePolicyJSON: %v", err)
	}

	if len(info.PCRs) != 2 {
		t.Fatalf("expected 2 PCRs, got %d", len(info.PCRs))
	}

	// PCRs should be in order they appear
	if info.PCRs[0] != 7 {
		t.Errorf("PCRs[0] = %d, want 7", info.PCRs[0])
	}
	if info.PCRs[1] != 0 {
		t.Errorf("PCRs[1] = %d, want 0", info.PCRs[1])
	}
}

func TestParsePolicyJSON_ArrayFormat(t *testing.T) {
	// systemd-pcrlock predict --json format: [{"pcr": 7}, {"pcr": 0}]
	data := `[{"pcr": 7, "digests": []}, {"pcr": 0, "digests": []}]`
	info, err := ParsePolicyJSON([]byte(data))
	if err != nil {
		t.Fatalf("ParsePolicyJSON: %v", err)
	}

	if len(info.PCRs) != 2 {
		t.Fatalf("expected 2 PCRs, got %d", len(info.PCRs))
	}
}

func TestParsePolicyJSON_Empty(t *testing.T) {
	_, err := ParsePolicyJSON([]byte(""))
	if err == nil {
		t.Error("expected error for empty data, got nil")
	}
}

func TestParsePolicyJSON_UnknownFormat(t *testing.T) {
	_, err := ParsePolicyJSON([]byte("42"))
	if err == nil {
		t.Error("expected error for unknown format, got nil")
	}
}

func TestParsePolicyJSON_DeduplicatesPCRs(t *testing.T) {
	// Array format with duplicate PCRs should deduplicate
	data := `[{"pcr": 7}, {"pcr": 7}, {"pcr": 0}]`
	info, err := ParsePolicyJSON([]byte(data))
	if err != nil {
		t.Fatalf("ParsePolicyJSON: %v", err)
	}

	if len(info.PCRs) != 2 {
		t.Errorf("expected 2 unique PCRs after dedup, got %d", len(info.PCRs))
	}
}

// --- Tests for GetPolicyNVIndex ---

func TestGetPolicyNVIndex(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"nvIndex": 27882256}`), 0644)

	idx, err := GetPolicyNVIndex(policyPath)
	if err != nil {
		t.Fatalf("GetPolicyNVIndex: %v", err)
	}

	if idx != 27882256 {
		t.Errorf("NVIndex = %d, want 27882256", idx)
	}
}

func TestGetPolicyNVIndex_NoIndex(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"pcrValues": []}`), 0644)

	idx, err := GetPolicyNVIndex(policyPath)
	if err != nil {
		t.Fatalf("GetPolicyNVIndex: %v", err)
	}

	if idx != 0 {
		t.Errorf("NVIndex = %d, want 0", idx)
	}
}

// --- Tests for Predict ---

func TestPredict(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"pcrValues": [{"pcr": 7, "values": ["abc"]}, {"pcr": 0, "values": ["def"]}]}`), 0644)

	pcrs, err := Predict(policyPath)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}

	if !pcrs[7] {
		t.Error("expected PCR 7 to be true")
	}
	if !pcrs[0] {
		t.Error("expected PCR 0 to be true")
	}
	if pcrs[4] {
		t.Error("expected PCR 4 to be false")
	}
}

func TestPredict_Empty(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "empty.json")
	os.WriteFile(policyPath, []byte(`{"pcrValues": []}`), 0644)

	pcrs, err := Predict(policyPath)
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}

	if len(pcrs) != 0 {
		t.Errorf("expected empty map, got %d entries", len(pcrs))
	}
}

// --- Tests for VerifyPolicy ---

func TestVerifyPolicy_AllPresent(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"pcrValues": [{"pcr": 7, "values": ["abc"]}, {"pcr": 0, "values": ["def"]}]}`), 0644)

	err := VerifyPolicy(policyPath, []int{7, 0})
	if err != nil {
		t.Errorf("VerifyPolicy should pass when all required PCRs present: %v", err)
	}
}

func TestVerifyPolicy_MissingPCR(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"pcrValues": [{"pcr": 7, "values": ["abc"]}]}`), 0644)

	err := VerifyPolicy(policyPath, []int{7, 4})
	if err == nil {
		t.Error("expected error for missing PCR 4")
	}
}

func TestVerifyPolicy_EmptyRequired(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"pcrValues": []}`), 0644)

	err := VerifyPolicy(policyPath, []int{})
	if err != nil {
		t.Errorf("VerifyPolicy with empty required should pass: %v", err)
	}
}

// --- Tests for extractNVPublicDetails ---

func TestExtractNVPublicDetails_Valid(t *testing.T) {
	// Build a TPM2B_NV_PUBLIC with no authPolicy:
	// [2 size][4 nvIndex][2 nameAlg=SHA256][4 attributes][2 authPolicySize=0][2 dataSize]
	data := make([]byte, 16)
	data[0], data[1] = 14, 0
	data[2], data[3], data[4], data[5] = 0x01, 0x80, 0x00, 0x01
	data[6], data[7] = 0x00, 0x0B
	data[8], data[9], data[10], data[11] = 0, 0, 0, 0
	data[12], data[13] = 0, 0
	data[14], data[15] = 0, 34

	b64 := base64.StdEncoding.EncodeToString(data)
	authPolicy, size, err := extractNVPublicDetails(b64)
	if err != nil {
		t.Fatalf("extractNVPublicDetails: %v", err)
	}

	if size != 34 {
		t.Errorf("dataSize = %d, want 34", size)
	}

	if authPolicy != "" {
		t.Errorf("authPolicy = %q, want empty", authPolicy)
	}
}

func TestExtractNVPublicDetails_InvalidBase64(t *testing.T) {
	_, _, err := extractNVPublicDetails("!!!not base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestExtractNVPublicDetails_TooShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	_, _, err := extractNVPublicDetails(short)
	if err == nil {
		t.Error("expected error for too-short data, got nil")
	}
}

// --- Tests for PCRNames ---

func TestPCRNames_KnownPCRs(t *testing.T) {
	expected := map[int]string{
		0:  "platform-code",
		7:  "secure-boot-policy",
		9:  "kernel-cmdline",
		11: "kernel-boot",
	}

	for pcr, expectedName := range expected {
		name, ok := PCRNames[pcr]
		if !ok {
			t.Errorf("PCR %d not in PCRNames", pcr)
			continue
		}
		if name != expectedName {
			t.Errorf("PCRNames[%d] = %q, want %q", pcr, name, expectedName)
		}
	}
}

func TestPCRNames_OmitsPCR6(t *testing.T) {
	if _, ok := PCRNames[6]; ok {
		t.Error("PCR 6 should not be in PCRNames (power-on events)")
	}
}
