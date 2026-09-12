// Package hotp implements RFC 4226 HMAC-based One-Time Passwords (HOTP)
// using HMAC-SHA256. It is designed for the vanguard boot recovery system,
// where a user enters a counter-based one-time code from an authenticator
// app to authorize passphrase fallback when TPM2 unseal fails in strict mode.
//
// HOTP is used instead of TOTP (RFC 6238) because the initramfs has no
// trustworthy clock: the RTC may be reset (dead CMOS battery, firmware
// update) and there is no network for NTP. TOTP validation is therefore
// only as reliable as the RTC plus a TPM-stored reference timestamp, which
// proved fragile in practice. HOTP depends on no clock at all — only a
// monotonically advancing counter persisted in TPM NVRAM.
//
// Parameters:
//   - Algorithm: HMAC-SHA256 (same primitive as the previous TOTP design;
//     the seed is a 256-bit key)
//   - Digits: 8 (compatible with Aegis, FreeOTP, KeePassXC, Google
//     Authenticator, Microsoft Authenticator, etc.)
//   - Counter: 64-bit, stored in TPM NVRAM, advanced on every successful use
//   - Lookahead: a small forward window tolerates an authenticator app whose
//     counter has advanced past the stored value
//
// Zero external dependencies — uses only crypto/hmac, crypto/sha1,
// crypto/sha256, crypto/subtle, and encoding/base32.
package hotp

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
)

const (
	// Digits is the number of digits in a HOTP code. 8 digits gives the
	// strongest online-guessing resistance for a code that only gates the
	// passphrase prompt (the passphrase remains the real secret).
	Digits = 8

	// SeedSize is the recommended seed size in bytes (256-bit HMAC-SHA256 key).
	SeedSize = 32

	// Lookahead is the number of counters past the stored value that are
	// accepted, to tolerate an authenticator app that has advanced on its
	// own (e.g. the user pressed "next" or a second device was enrolled).
	// The accepted window is [stored, stored+Lookahead].
	//
	// Security: each additional position linearly widens the guessing
	// space. With 3 attempts per boot and Lookahead=4, the per-boot
	// brute-force probability is 3*(4+1)/10^6 = 1.5e-5. The persistent
	// fail counter (see recovery) bounds cross-boot accumulation.
	Lookahead = 4
)

// GenerateCode computes an 8-digit HOTP code for the given secret and counter.
// Uses HMAC-SHA256 with RFC 4226 dynamic truncation.
func GenerateCode(secret []byte, counter uint64) string {
	return generateCode(secret, counter, sha256.New, Digits)
}

// GenerateCodeSHA1 computes a HOTP code using HMAC-SHA1. Provided for
// cross-checking against RFC 4226 test vectors.
func GenerateCodeSHA1(secret []byte, counter uint64) string {
	return generateCode(secret, counter, sha1.New, Digits)
}

// generateCode is the core HOTP generation function.
// It implements RFC 4226 §5.3 (dynamic truncation).
func generateCode(secret []byte, counter uint64, hashFunc func() hash.Hash, digits int) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(hashFunc, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 §5.3
	offset := int(sum[len(sum)-1] & 0xf)
	value := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	code := value % int(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code)
}

// Validate checks whether code matches HOTP for any counter in the window
// [stored, stored+lookahead], using constant-time comparison. On success it
// returns the matched counter and true; otherwise 0 and false.
//
// The caller is expected to persist matched+1 as the new stored counter so
// that the accepted code (and all earlier ones) can never be reused.
func Validate(code string, secret []byte, stored uint64, lookahead uint) (uint64, bool) {
	if len(code) != Digits {
		return 0, false
	}

	codeBytes := []byte(code)
	for i := uint64(0); i <= uint64(lookahead); i++ {
		counter := stored + i
		candidate := GenerateCode(secret, counter)
		if subtle.ConstantTimeCompare(codeBytes, []byte(candidate)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

// GenerateSeed returns a cryptographically random 32-byte seed.
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

// BuildOTPAuthURI constructs an otpauth:// URI for QR code enrollment in
// authenticator apps that support HOTP (Aegis, FreeOTP, KeePassXC,
// Bitwarden, Google Authenticator, Microsoft Authenticator, ...).
//
// Format: otpauth://hotp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&algorithm=SHA256&digits=8&counter=<n>
func BuildOTPAuthURI(secret []byte, issuer, account string, counter uint64) string {
	secretB32 := EncodeBase32(secret)
	return fmt.Sprintf("otpauth://hotp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&counter=%d",
		issuer, account, secretB32, issuer, Digits, counter)
}
