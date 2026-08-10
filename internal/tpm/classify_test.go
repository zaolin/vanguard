package tpm

import (
	"errors"
	"fmt"
	"testing"
)

// --- Tests for classifyUnsealError ---

func TestClassifyUnsealError_Lockout(t *testing.T) {
	// Lockout should always return ErrTPMLockout regardless of usePCRLock
	err := classifyUnsealError(fmt.Errorf("TPM_RC_LOCKOUT"), false)
	if !errors.Is(err, ErrTPMLockout) {
		t.Errorf("expected ErrTPMLockout, got: %v", err)
	}

	err = classifyUnsealError(fmt.Errorf("TPM_RC_LOCKOUT"), true)
	if !errors.Is(err, ErrTPMLockout) {
		t.Errorf("expected ErrTPMLockout for pcrlock, got: %v", err)
	}
}

func TestClassifyUnsealError_AuthFail_Traditional(t *testing.T) {
	// Traditional tokens should distinguish ErrWrongPIN
	err := classifyUnsealError(fmt.Errorf("TPM_RC_AUTH_FAIL"), false)
	if !errors.Is(err, ErrWrongPIN) {
		t.Errorf("expected ErrWrongPIN for traditional, got: %v", err)
	}
}

func TestClassifyUnsealError_AuthFail_Pcrlock(t *testing.T) {
	// pcrlock tokens should collapse to ErrPolicyFailed
	err := classifyUnsealError(fmt.Errorf("TPM_RC_AUTH_FAIL"), true)
	if !errors.Is(err, ErrPolicyFailed) {
		t.Errorf("expected ErrPolicyFailed for pcrlock, got: %v", err)
	}
	if errors.Is(err, ErrWrongPIN) {
		t.Error("should not be ErrWrongPIN for pcrlock — error oracle prevention")
	}
}

func TestClassifyUnsealError_PolicyFail_Traditional(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("TPM_RC_POLICY_FAIL"), false)
	if !errors.Is(err, ErrPCRMismatch) {
		t.Errorf("expected ErrPCRMismatch for traditional, got: %v", err)
	}
}

func TestClassifyUnsealError_PolicyFail_Pcrlock(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("TPM_RC_POLICY_FAIL"), true)
	if !errors.Is(err, ErrPolicyFailed) {
		t.Errorf("expected ErrPolicyFailed for pcrlock, got: %v", err)
	}
	if errors.Is(err, ErrPCRMismatch) {
		t.Error("should not be ErrPCRMismatch for pcrlock — error oracle prevention")
	}
}

func TestClassifyUnsealError_StringMatch_AuthFail(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("HMAC check failed"), true)
	if !errors.Is(err, ErrPolicyFailed) {
		t.Errorf("expected ErrPolicyFailed for string-matched auth failure, got: %v", err)
	}
}

func TestClassifyUnsealError_StringMatch_PolicyFail(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("POLICY_FAIL error"), true)
	if !errors.Is(err, ErrPolicyFailed) {
		t.Errorf("expected ErrPolicyFailed for string-matched policy failure, got: %v", err)
	}
}

func TestClassifyUnsealError_StringMatch_Lockout(t *testing.T) {
	err := classifyUnsealError(fmt.Errorf("LOCKOUT active"), true)
	if !errors.Is(err, ErrTPMLockout) {
		t.Errorf("expected ErrTPMLockout for string-matched lockout, got: %v", err)
	}
}

func TestClassifyUnsealError_UnknownError(t *testing.T) {
	origErr := fmt.Errorf("something completely unknown")
	err := classifyUnsealError(origErr, true)
	if err != origErr {
		t.Errorf("unknown error should pass through, got: %v", err)
	}
}

// --- Tests for isValidNVIndex ---

func TestIsValidNVIndex(t *testing.T) {
	tests := []struct {
		idx  uint32
		want bool
	}{
		{0x01000000, false},
		{0x01800000, true},
		{0x01A97310, true},
		{0x01BFFFFF, true},
		{0x01FFFFFF, true},
		{0x00800000, false},
		{0x02000000, true}, // platform hierarchy range is valid
		{0xDEADBEEF, false},
		{0x00000000, false},
		{0x01C20000, true},
	}

	for _, tt := range tests {
		got := isValidNVIndex(tt.idx)
		if got != tt.want {
			t.Errorf("isValidNVIndex(0x%x) = %v, want %v", tt.idx, got, tt.want)
		}
	}
}

// --- Tests for ParsePCRBank ---

func TestParsePCRBank(t *testing.T) {
	tests := []struct {
		bank string
		want HashAlgorithm
	}{
		{"sha256", AlgSHA256},
		{"sha1", AlgSHA1},
		{"sha384", AlgSHA384},
		{"sha512", AlgSHA512},
		{"", AlgSHA256},        // default
		{"SHA256", AlgSHA256},  // default for unknown
		{"unknown", AlgSHA256}, // default for unknown
	}

	for _, tt := range tests {
		got := ParsePCRBank(tt.bank)
		if got != tt.want {
			t.Errorf("ParsePCRBank(%q) = 0x%x, want 0x%x", tt.bank, got, tt.want)
		}
	}
}

// --- Tests for ParseBlob edge cases ---

func TestParseBlob_TooShort(t *testing.T) {
	_, _, err := ParseBlob([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for too-short blob, got nil")
	}
}

func TestParseBlob_Empty(t *testing.T) {
	_, _, err := ParseBlob(nil)
	if err == nil {
		t.Error("expected error for nil blob, got nil")
	}
}

func TestParseBlob_ValidMinimal(t *testing.T) {
	// Minimal valid blob: [2-byte private size][private][2-byte public size][public]
	priv := []byte{0xAA, 0xBB}
	pub := []byte{0xCC, 0xDD}
	blob := make([]byte, 0)
	blob = append(blob, byte(len(priv)>>8), byte(len(priv)))
	blob = append(blob, priv...)
	blob = append(blob, byte(len(pub)>>8), byte(len(pub)))
	blob = append(blob, pub...)

	gotPriv, gotPub, err := ParseBlob(blob)
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}

	if len(gotPriv) != len(priv) {
		t.Errorf("private length: got %d, want %d", len(gotPriv), len(priv))
	}

	if len(gotPub) != len(pub) {
		t.Errorf("public length: got %d, want %d", len(gotPub), len(pub))
	}
}
