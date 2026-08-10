// Package totp implements RFC 6238 TOTP (Time-Based One-Time Password)
// using HMAC-SHA256. It is designed for the vanguard boot recovery system
// where a user enters a 6-digit code from their authenticator app to
// authorize passphrase fallback when TPM2 unseal fails in strict mode.
//
// Parameters:
//   - Algorithm: HMAC-SHA256 (RFC 6238 §1.2)
//   - Period: 30 seconds (RFC 6238 default)
//   - Digits: 6 (compatible with Google Authenticator, Authy, etc.)
//   - Seed: 32 bytes (256-bit secret)
//   - Skew: ±1 window by default (90s tolerance), ±120 when RTC drift detected
//
// Zero external dependencies — uses only crypto/hmac, crypto/sha256,
// crypto/subtle, encoding/binary, encoding/base32, and time.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

const (
	// Period is the TOTP time step in seconds (RFC 6238 default).
	Period = 30

	// Digits is the number of digits in the TOTP code.
	Digits = 6

	// SeedSize is the recommended seed size in bytes (256-bit HMAC-SHA256 key).
	SeedSize = 32

	// DefaultSkew is the default ±window tolerance (±1 = 90s total).
	DefaultSkew = 1

	// DriftSkew is the widened tolerance when RTC drift is detected (±10 = ±5min).
	// This covers typical RTC drift from a dead CMOS battery (minutes, not hours)
	// while limiting the attack surface: 21 valid windows × 3 attempts = 63/10^6
	// ≈ 0.006% brute-force probability per recovery session, vs 90s default.
	DriftSkew = 10
)

// GenerateCode computes a 6-digit TOTP code for the given secret and time.
// Uses HMAC-SHA256 with a 30-second period per RFC 6238.
func GenerateCode(secret []byte, t time.Time) string {
	return generateCode(secret, t, sha256.New, Period, Digits)
}

// GenerateCodeSHA1 computes a TOTP code using HMAC-SHA1. This is provided
// for cross-checking against RFC 4226 HOTP test vectors.
func GenerateCodeSHA1(secret []byte, t time.Time) string {
	return generateCode(secret, t, sha1.New, Period, Digits)
}

// generateCode is the core TOTP/HOTP generation function.
// It implements RFC 4226 §5.3 (dynamic truncation) and RFC 6238 §4.2.
func generateCode(secret []byte, t time.Time, hashFunc func() hash.Hash, period uint, digits int) string {
	counter := uint64(t.Unix()) / uint64(period)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(hashFunc, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 §5.3
	offset := int(sum[len(sum)-1] & 0xf)
	// Assemble 4 bytes big-endian, masking high bit of first byte (31-bit unsigned)
	value := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	code := value % int(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code)
}

// Validate checks if the provided code matches the TOTP for the given time
// with ±skew windows of tolerance. Uses constant-time comparison to prevent
// timing attacks.
//
// For normal operation, use DefaultSkew (±1 = 90s tolerance).
// When RTC drift is detected, use DriftSkew (±10 = ±5min tolerance).
func Validate(code string, secret []byte, t time.Time, skew uint) bool {
	if len(code) != Digits {
		return false
	}

	counter := int64(t.Unix()) / Period

	for i := -int64(skew); i <= int64(skew); i++ {
		candidateTime := time.Unix((counter+i)*Period, 0)
		candidate := GenerateCode(secret, candidateTime)
		if subtle.ConstantTimeCompare([]byte(code), []byte(candidate)) == 1 {
			return true
		}
	}

	return false
}

// GenerateSeed generates a cryptographically random 32-byte TOTP seed.
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return seed, nil
}

// EncodeBase32 encodes a raw secret as RFC 4648 base32 without padding,
// for authenticator app enrollment (Google Authenticator format).
func EncodeBase32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// DecodeBase32 decodes a base32-encoded secret string back to raw bytes.
// Handles missing padding and lowercase input.
func DecodeBase32(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)
	if n := len(s) % 8; n != 0 {
		s += strings.Repeat("=", 8-n)
	}
	return base32.StdEncoding.DecodeString(s)
}

// BuildOTPAuthURI constructs an otpauth:// URI for QR code enrollment
// in authenticator apps (Google Authenticator, Authy, 1Password, etc.).
//
// Format: otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&algorithm=SHA256&digits=6&period=30
func BuildOTPAuthURI(secret []byte, issuer, account string) string {
	secretB32 := EncodeBase32(secret)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&period=%d",
		issuer, account, secretB32, issuer, Digits, Period)
}
