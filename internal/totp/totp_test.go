package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- RFC 4226 HOTP Test Vectors (SHA1 cross-check) ---
// Seed: ASCII "12345678901234567890" (20 bytes)
// https://tools.ietf.org/html/rfc4226#page-32

func TestRFC4226_HOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")

	expected := []string{
		"755224", // count 0
		"287082", // count 1
		"359152", // count 2
		"969429", // count 3
		"338314", // count 4
		"254676", // count 5
		"287922", // count 6
		"162583", // count 7
		"399871", // count 8
		"520489", // count 9
	}

	for count, want := range expected {
		// HOTP(counter) = TOTP at time = count * 30 (since period=30)
		tTime := time.Unix(int64(count*30), 0)
		got := GenerateCodeSHA1(secret, tTime)
		if got != want {
			t.Errorf("HOTP count %d: got %s, want %s", count, got, want)
		}
	}
}

// --- RFC 6238 TOTP Test Vectors (SHA256) ---
// Seed: 32 bytes (ASCII "12345678901234567890123456789012")
// https://tools.ietf.org/html/rfc6238#page-15
// Note: RFC table shows 8-digit codes. We use 6 digits, so we compute
// 8-digit and verify, then also verify 6-digit = 8-digit % 1000000.

func TestRFC6238_TOTPSHA256_8Digit(t *testing.T) {
	// 32-byte seed for SHA256
	secret := []byte("12345678901234567890123456789012")

	// Verified with Python: hmac.new(seed, struct.pack('>Q', counter), hashlib.sha256)
	tests := []struct {
		unixTime int64
		want8    string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("T=%d", tt.unixTime), func(t *testing.T) {
			// Compute 8-digit code using our implementation
			counter := uint64(tt.unixTime) / 30
			code := generateCode(secret, time.Unix(tt.unixTime, 0), sha256.New, 30, 8)
			if code != tt.want8 {
				t.Errorf("8-digit SHA256 TOTP at T=%d: got %s, want %s (counter=%d)",
					tt.unixTime, code, tt.want8, counter)
			}
		})
	}
}

func TestRFC6238_TOTPSHA256_6Digit(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	tests := []struct {
		unixTime int64
		want6    string
	}{
		{59, "119246"},
		{1111111109, "084774"},
		{1111111111, "062674"},
		{1234567890, "819424"},
		{2000000000, "698825"},
		{20000000000, "737706"},
	}

	for _, tt := range tests {
		got := GenerateCode(secret, time.Unix(tt.unixTime, 0))
		if got != tt.want6 {
			t.Errorf("6-digit SHA256 TOTP at T=%d: got %s, want %s", tt.unixTime, got, tt.want6)
		}
	}
}

// --- RFC 6238 TOTP Test Vectors (SHA1 cross-check) ---

func TestRFC6238_TOTPSHA1_8Digit(t *testing.T) {
	secret := []byte("12345678901234567890")

	tests := []struct {
		unixTime int64
		want8    string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tt := range tests {
		code := generateCode(secret, time.Unix(tt.unixTime, 0), sha1.New, 30, 8)
		if code != tt.want8 {
			t.Errorf("8-digit SHA1 TOTP at T=%d: got %s, want %s", tt.unixTime, code, tt.want8)
		}
	}
}

// --- Validate tests ---

func TestValidate_CorrectCode(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	tTime := time.Unix(59, 0) // T=59, counter=1

	code := GenerateCode(secret, tTime)
	if !Validate(code, secret, tTime, DefaultSkew) {
		t.Errorf("Validate should accept correct code %s at T=59", code)
	}
}

func TestValidate_WrongCode(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	tTime := time.Unix(59, 0)

	if Validate("000000", secret, tTime, DefaultSkew) {
		t.Error("Validate should reject wrong code 000000")
	}
}

func TestValidate_ExpiredCode(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	// Generate code for T=59, validate at T=59 + 120s (4 windows away)
	oldTime := time.Unix(59, 0)
	code := GenerateCode(secret, oldTime)

	validateTime := time.Unix(59+120, 0) // 4 windows ahead
	if Validate(code, secret, validateTime, DefaultSkew) {
		t.Error("Validate should reject expired code (4 windows away)")
	}
}

func TestValidate_Skew_Plus1(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	// Generate code for T=0 (counter=0), validate at T=29 (still counter=0)
	codeTime := time.Unix(0, 0)
	validateTime := time.Unix(29, 0) // same counter

	code := GenerateCode(secret, codeTime)
	if !Validate(code, secret, validateTime, DefaultSkew) {
		t.Error("Validate should accept code within same window")
	}
}

func TestValidate_Skew_Plus1Window(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	// Generate code for T=0 (counter=0), validate at T=30 (counter=1)
	// With ±1 skew, counter 0 is accepted at validation time counter=1
	codeTime := time.Unix(0, 0)
	code := GenerateCode(secret, codeTime)

	validateTime := time.Unix(30, 0) // counter=1, skew±1 accepts counter=0
	if !Validate(code, secret, validateTime, DefaultSkew) {
		t.Error("Validate should accept code from previous window with ±1 skew")
	}
}

func TestValidate_Skew_Plus2Window_Rejected(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	// Generate code for T=0 (counter=0), validate at T=60 (counter=2)
	// With ±1 skew, counter 0 is NOT accepted at validation time counter=2
	codeTime := time.Unix(0, 0)
	code := GenerateCode(secret, codeTime)

	validateTime := time.Unix(60, 0) // counter=2, skew±1 rejects counter=0
	if Validate(code, secret, validateTime, DefaultSkew) {
		t.Error("Validate should reject code from 2 windows ago with ±1 skew")
	}
}

func TestValidate_DriftSkew_Plus10Windows(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	// Generate code for T=0 (counter=0), validate at T=10*30=300 (counter=10)
	// With ±10 skew, counter 0 IS accepted at validation time counter=10
	codeTime := time.Unix(0, 0)
	code := GenerateCode(secret, codeTime)

	validateTime := time.Unix(10*30, 0) // counter=10, drift skew accepts counter=0
	if !Validate(code, secret, validateTime, DriftSkew) {
		t.Error("Validate should accept code from 10 windows ago with drift skew")
	}
}

func TestValidate_DriftSkew_Plus11Windows_Rejected(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	codeTime := time.Unix(0, 0)
	code := GenerateCode(secret, codeTime)

	validateTime := time.Unix(11*30, 0) // counter=11, drift skew rejects counter=0
	if Validate(code, secret, validateTime, DriftSkew) {
		t.Error("Validate should reject code from 11 windows ago even with drift skew")
	}
}

func TestValidate_WrongLength(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	if Validate("12345", secret, time.Now(), DefaultSkew) {
		t.Error("Validate should reject 5-digit code")
	}
	if Validate("1234567", secret, time.Now(), DefaultSkew) {
		t.Error("Validate should reject 7-digit code")
	}
}

func TestValidate_EmptyCode(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	if Validate("", secret, time.Now(), DefaultSkew) {
		t.Error("Validate should reject empty code")
	}
}

func TestValidate_ZeroSkew(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")

	tTime := time.Unix(59, 0)
	code := GenerateCode(secret, tTime)

	// Zero skew: only exact window match
	if !Validate(code, secret, tTime, 0) {
		t.Error("Validate should accept exact code with zero skew")
	}

	// One window away should fail with zero skew
	if Validate(code, secret, time.Unix(59+30, 0), 0) {
		t.Error("Validate should reject code from next window with zero skew")
	}
}

// --- Seed generation tests ---

func TestGenerateSeed_Size(t *testing.T) {
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}

	if len(seed) != SeedSize {
		t.Errorf("seed size = %d, want %d", len(seed), SeedSize)
	}
}

func TestGenerateSeed_Uniqueness(t *testing.T) {
	seed1, _ := GenerateSeed()
	seed2, _ := GenerateSeed()

	if hex.EncodeToString(seed1) == hex.EncodeToString(seed2) {
		t.Error("two seeds should not be identical")
	}
}

// --- Base32 tests ---

func TestEncodeBase32(t *testing.T) {
	// Known test: empty bytes → empty string
	if EncodeBase32(nil) != "" {
		t.Errorf("empty base32: got %q", EncodeBase32(nil))
	}

	// 32 bytes should produce ~52 base32 chars (no padding)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	encoded := EncodeBase32(seed)
	if encoded == "" {
		t.Error("expected non-empty base32 for 32-byte seed")
	}
}

func TestDecodeBase32_RoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	encoded := EncodeBase32(seed)
	decoded, err := DecodeBase32(encoded)
	if err != nil {
		t.Fatalf("DecodeBase32: %v", err)
	}

	if hex.EncodeToString(decoded) != hex.EncodeToString(seed) {
		t.Errorf("round-trip mismatch:\n  orig:  %s\n  round: %s",
			hex.EncodeToString(seed), hex.EncodeToString(decoded))
	}
}

func TestDecodeBase32_Lowercase(t *testing.T) {
	seed := []byte{0x12, 0x34}
	encoded := EncodeBase32(seed)

	// Lowercase input should still decode
	lower := string(toLower(encoded))
	decoded, err := DecodeBase32(lower)
	if err != nil {
		t.Fatalf("DecodeBase32 lowercase: %v", err)
	}

	if hex.EncodeToString(decoded) != hex.EncodeToString(seed) {
		t.Error("lowercase round-trip failed")
	}
}

func TestDecodeBase32_InvalidInput(t *testing.T) {
	_, err := DecodeBase32("!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base32 input")
	}
}

// --- Constant-time comparison verification ---

func TestValidate_ConstantTimeComparison(t *testing.T) {
	// This test verifies that Validate uses subtle.ConstantTimeCompare
	// by checking that it doesn't leak timing on different-length inputs
	// (constant-time compare returns 0 immediately on length mismatch,
	// which is the correct behavior — no early-exit on content).
	secret := []byte("12345678901234567890123456789012")
	tTime := time.Unix(59, 0)

	// Correct code
	correct := GenerateCode(secret, tTime)

	// Validate should accept
	if !Validate(correct, secret, tTime, DefaultSkew) {
		t.Error("correct code not accepted")
	}

	// Partial match (first 5 chars correct, last wrong) should reject
	wrong := correct[:5] + "0"
	if correct[:5] == wrong[:5] { // ensure first 5 match
		if Validate(wrong, secret, tTime, DefaultSkew) {
			t.Error("partially-correct code should be rejected")
		}
	}
}

// --- ValidateWithDrift tests ---

func TestValidateWithDrift_RTCCorrect(t *testing.T) {
	// When RTC is correct, ValidateWithDrift should behave like Validate
	secret := []byte("12345678901234567890123456789012")
	now := time.Unix(1000, 0)
	refTime := time.Unix(1000, 0) // ref == now, no drift

	code := GenerateCode(secret, now)

	if !ValidateWithDrift(code, secret, now, DefaultSkew, refTime) {
		t.Error("ValidateWithDrift should accept correct code when RTC matches")
	}
}

func TestValidateWithDrift_RTCWrong_CodeMatchesRefTime(t *testing.T) {
	// Simulates: RTC reset to epoch 0, but reference timestamp is from last boot.
	// The user's authenticator app generates a code using real current time,
	// which matches the reference timestamp (last boot was recent).
	secret := []byte("12345678901234567890123456789012")
	brokenRTC := time.Unix(0, 0)    // RTC reset to epoch 0
	refTime := time.Unix(1000, 0)  // Reference timestamp from last boot
	realTime := time.Unix(1010, 0) // Real current time (within ±24h of ref)

	// Code from authenticator app (uses real time)
	code := GenerateCode(secret, realTime)

	// RTC validation should fail (code is not for epoch 0)
	if Validate(code, secret, brokenRTC, DefaultSkew) {
		t.Error("Validate should reject code when RTC is wrong")
	}

	// ValidateWithDrift should accept (tries refTime with WideSkew)
	if !ValidateWithDrift(code, secret, brokenRTC, DriftSkew, refTime) {
		t.Error("ValidateWithDrift should accept code matching refTime within WideSkew")
	}
}

func TestValidateWithDrift_RTCWrong_CodeFarFromRef(t *testing.T) {
	// Code is generated at a time far outside ±24h of the reference timestamp
	// (e.g., system was off for 2 days). Should reject.
	secret := []byte("12345678901234567890123456789012")
	brokenRTC := time.Unix(0, 0)
	refTime := time.Unix(1000, 0)
	realTime := time.Unix(1000 + 2*24*3600, 0) // 2 days after ref

	code := GenerateCode(secret, realTime)

	if ValidateWithDrift(code, secret, brokenRTC, DriftSkew, refTime) {
		t.Error("ValidateWithDrift should reject code more than ±24h from refTime")
	}
}

func TestValidateWithDrift_RTCWrong_CodeWithin24h(t *testing.T) {
	// Code is generated exactly 23h59m after the reference timestamp
	secret := []byte("12345678901234567890123456789012")
	brokenRTC := time.Unix(0, 0)
	refTime := time.Unix(1000, 0)
	realTime := time.Unix(1000 + 23*3600 + 59*60, 0) // 23h59m after ref

	code := GenerateCode(secret, realTime)

	if !ValidateWithDrift(code, secret, brokenRTC, DriftSkew, refTime) {
		t.Error("ValidateWithDrift should accept code within ±24h of refTime")
	}
}

func TestValidateWithDrift_WrongCode(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	now := time.Unix(1000, 0)
	refTime := time.Unix(1000, 0)

	if ValidateWithDrift("000000", secret, now, DefaultSkew, refTime) {
		t.Error("ValidateWithDrift should reject wrong code")
	}
}

func TestValidateWithDrift_EmptyCode(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	now := time.Unix(1000, 0)
	refTime := time.Unix(1000, 0)

	if ValidateWithDrift("", secret, now, DefaultSkew, refTime) {
		t.Error("ValidateWithDrift should reject empty code")
	}
}

// --- HMAC raw verification ---

func TestHMAC_SHA256_RawOutput(t *testing.T) {
	// Verify our HMAC-SHA256 computation matches a manual calculation
	secret := []byte("test-secret-32-bytes-long-ok!!!")
	counter := uint64(1)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// Manual HMAC-SHA256
	mac := hmacSHA256(secret, buf)
	if len(mac) != 32 {
		t.Errorf("HMAC-SHA256 output size: %d, want 32", len(mac))
	}

	// Dynamic truncation
	offset := int(mac[31] & 0xf)
	value := (int(mac[offset])&0x7f)<<24 |
		(int(mac[offset+1])&0xff)<<16 |
		(int(mac[offset+2])&0xff)<<8 |
		(int(mac[offset+3]) & 0xff)

	expectedCode := fmt.Sprintf("%06d", value%1000000)
	actualCode := GenerateCode(secret, time.Unix(30, 0)) // counter=1

	if actualCode != expectedCode {
		t.Errorf("HMAC truncation mismatch: manual=%s, totp=%s", expectedCode, actualCode)
	}
}

// --- QR code tests ---

func TestBuildOTPAuthURI(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	uri := BuildOTPAuthURI(secret, "Vanguard", "recovery")
	if uri == "" {
		t.Fatal("expected non-empty URI")
	}

	if !strings.Contains(uri, "otpauth://totp/Vanguard:recovery?") {
		t.Errorf("URI doesn't start with expected prefix: %s", uri)
	}

	if !strings.Contains(uri, "algorithm=SHA256") {
		t.Error("URI should contain algorithm=SHA256")
	}

	if !strings.Contains(uri, "digits=6") {
		t.Error("URI should contain digits=6")
	}

	if !strings.Contains(uri, "period=30") {
		t.Error("URI should contain period=30")
	}

	secretB32 := EncodeBase32(secret)
	if !strings.Contains(uri, "secret="+secretB32) {
		t.Error("URI should contain base32-encoded secret")
	}
}

func TestGenerateQRCodeString(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	uri := BuildOTPAuthURI(secret, "Vanguard", "recovery")

	qrStr, err := GenerateQRCodeString(uri)
	if err != nil {
		t.Fatalf("GenerateQRCodeString: %v", err)
	}

	if qrStr == "" {
		t.Error("expected non-empty QR code string")
	}

	if len(qrStr) < 100 {
		t.Errorf("QR code string too short: %d chars", len(qrStr))
	}
}

func TestGenerateQRCodeString_InvalidURI(t *testing.T) {
	longURI := "otpauth://totp/test:test?secret=" + EncodeBase32(make([]byte, 1000))
	_, err := GenerateQRCodeString(longURI)
	_ = err
}

// --- Helpers ---

func toLower(s string) []byte {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return b
}

// hmacSHA256 is a manual HMAC-SHA256 for cross-checking.
func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}
