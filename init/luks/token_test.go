package luks

import (
	"encoding/base64"
	"testing"
)

func TestUnsealedSecretBase64Encoding(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	encoded := base64.StdEncoding.EncodeToString(secret)

	if len(encoded) != 44 {
		t.Errorf("base64 of 32 bytes: got %d chars, want 44", len(encoded))
	}

	expected := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	if encoded != expected {
		t.Errorf("encoded mismatch:\n  got:    %s\n  want:   %s", encoded, expected)
	}

	t.Logf("base64(32 bytes) = %q (%d chars)", encoded, len(encoded))

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded length: got %d, want 32", len(decoded))
	}
}

func TestUnsealedSecretBase64EncodingSystemdCompat(t *testing.T) {
	testSecrets := [][]byte{
		make([]byte, 32),
		{0x01, 0x02, 0x03},
		{0xFF, 0xFE, 0xFD},
	}

	for _, secret := range testSecrets {
		encoded := base64.StdEncoding.EncodeToString(secret)

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("round-trip failed for %x: %v", secret, err)
			continue
		}
		if len(decoded) != len(secret) {
			t.Errorf("round-trip length mismatch: %d vs %d", len(decoded), len(secret))
		}
	}
}

func TestUnsealedSecretBase64NoTrailingNewline(t *testing.T) {
	secret := make([]byte, 32)
	encoded := base64.StdEncoding.EncodeToString(secret)

	if len(encoded) > 0 && encoded[len(encoded)-1] == '\n' {
		t.Error("base64 encoded string has trailing newline")
	}

	t.Logf("encoded = %q (last char = %q)", encoded, encoded[len(encoded)-1])
}
