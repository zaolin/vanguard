package hotp

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// TestRFC4226_SHA1Vectors checks the HOTP core against RFC 4226 Appendix D.
// The RFC vectors are 6-digit; the 8-digit values are the same dynamic-
// truncation values reduced mod 10^8 (the RFC 6-digit value is the last 6
// digits of the 8-digit value).
func TestRFC4226_SHA1Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{
		"84755224", "94287082", "37359152", "26969429", "40338314",
		"68254676", "18287922", "82162583", "73399871", "45520489",
	}
	for counter, expected := range want {
		got := GenerateCodeSHA1(secret, uint64(counter))
		if got != expected {
			t.Errorf("HOTP-SHA1 counter %d: got %s, want %s", counter, got, expected)
		}
	}
}

// TestRFC6238_SHA256Vectors cross-checks the SHA256 core against the
// independent Python HMAC computation; the 8-digit values match RFC 6238
// Appendix B for the SHA256 secret.
func TestRFC6238_SHA256Vectors(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	// 8-digit HOTP-SHA256 values derived independently (python hmac), which
	// equal RFC 6238 Appendix B SHA256 8-digit vectors.
	vectors := []struct {
		counter uint64
		want    string
	}{
		{1, "46119246"},
		{37037036, "68084774"},
		{37037037, "67062674"},
		{41152263, "91819424"},
		{66666666, "90698825"},
		{666666666, "77737706"},
	}
	for _, v := range vectors {
		if got := GenerateCode(secret, v.counter); got != v.want {
			t.Errorf("HOTP-SHA256 counter %d: got %s, want %s", v.counter, got, v.want)
		}
	}
	_ = sha256.New
}

// TestValidate_ExactCounter accepts the code at the stored counter.
func TestValidate_ExactCounter(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	code := GenerateCode(secret, 7)
	matched, ok := Validate(code, secret, 7, Lookahead)
	if !ok || matched != 7 {
		t.Fatalf("Validate exact: matched=%d ok=%v, want 7,true", matched, ok)
	}
}

// TestValidate_LookaheadWindow accepts codes up to stored+lookahead.
func TestValidate_LookaheadWindow(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	for i := uint64(0); i <= Lookahead; i++ {
		code := GenerateCode(secret, 100+i)
		matched, ok := Validate(code, secret, 100, Lookahead)
		if !ok || matched != 100+i {
			t.Errorf("Validate lookahead +%d: matched=%d ok=%v, want %d,true", i, matched, ok, 100+i)
		}
	}
}

// TestValidate_RejectsBeyondLookahead rejects codes past the window.
func TestValidate_RejectsBeyondLookahead(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	code := GenerateCode(secret, 100+Lookahead+1)
	if _, ok := Validate(code, secret, 100, Lookahead); ok {
		t.Error("Validate accepted a code beyond the lookahead window")
	}
}

// TestValidate_RejectsBelowStored rejects a code at an already-consumed
// position (replay protection: the counter only moves forward).
func TestValidate_RejectsBelowStored(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	code := GenerateCode(secret, 99)
	if _, ok := Validate(code, secret, 100, Lookahead); ok {
		t.Error("Validate accepted an already-consumed (below stored) code")
	}
}

// TestValidate_RejectsWrongLength rejects non-6-digit input.
func TestValidate_RejectsWrongLength(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, ok := Validate("1234567", secret, 0, Lookahead); ok {
		t.Error("Validate accepted a 7-digit code")
	}
	if _, ok := Validate("123456789", secret, 0, Lookahead); ok {
		t.Error("Validate accepted a 9-digit code")
	}
}

// TestValidate_WrongCode rejects a random wrong code.
func TestValidate_WrongCode(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	// Find a code that is not valid in the small window.
	wrong := "00000000"
	for i := uint64(0); i <= Lookahead; i++ {
		if GenerateCode(secret, i) == wrong {
			wrong = "11111111"
		}
	}
	if _, ok := Validate(wrong, secret, 0, Lookahead); ok {
		t.Error("Validate accepted a wrong code")
	}
}

// TestGenerateSeed verifies seed size and non-determinism.
func TestGenerateSeed(t *testing.T) {
	a, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	if len(a) != SeedSize {
		t.Fatalf("seed size: got %d, want %d", len(a), SeedSize)
	}
	b, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	if string(a) == string(b) {
		t.Error("two generated seeds are identical")
	}
}

// TestBase32RoundTrip verifies encode/decode, including unpadded input.
func TestBase32RoundTrip(t *testing.T) {
	seed, _ := GenerateSeed()
	enc := EncodeBase32(seed)
	dec, err := DecodeBase32(enc)
	if err != nil {
		t.Fatalf("DecodeBase32: %v", err)
	}
	if string(dec) != string(seed) {
		t.Error("base32 round-trip mismatch")
	}
	// Lowercase input is accepted.
	if _, err := DecodeBase32(strings.ToLower(enc)); err != nil {
		t.Errorf("DecodeBase32(lowercase): %v", err)
	}
}

// TestBuildOTPAuthURI verifies the HOTP URI shape and counter field.
func TestBuildOTPAuthURI(t *testing.T) {
	seed := []byte("0123456789abcdef0123456789abcdef")
	uri := BuildOTPAuthURI(seed, "Vanguard", "recovery", 42)
	for _, want := range []string{
		"otpauth://hotp/Vanguard:recovery?",
		"algorithm=SHA256",
		"digits=8",
		"counter=42",
		"issuer=Vanguard",
		"secret=" + EncodeBase32(seed),
	} {
		if !contains(uri, want) {
			t.Errorf("URI %q missing %q", uri, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
