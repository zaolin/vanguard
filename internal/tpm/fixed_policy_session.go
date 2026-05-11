package tpm

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// fixedTrimAuth trims only trailing zero bytes from the auth value.
// This is the correct TPM spec behavior (Part 1, 19.6.5, Note 2).
// It replaces go-tpm's buggy hmacKeyFromAuthValue which over-trims
// non-trailing zero bytes due to a missing break statement.
func fixedTrimAuth(auth []byte) []byte {
	return bytes.TrimRight(auth, "\x00")
}

// fixedAuthPolicySession wraps a go-tpm policy session to fix the
// hmacKeyFromAuthValue bug. go-tpm v0.9.8's hmacKeyFromAuthValue()
// over-trims auth values that contain non-trailing zero bytes, causing
// TPM_RC_AUTH_FAIL when the computed HMAC key is shorter than the TPM's.
type fixedAuthPolicySession struct {
	inner tpm2.Session
	auth  []byte
}

// newFixedAuthPolicySession creates a policy session with correct HMAC key trimming.
// It creates the session normally via go-tpm, then wraps it to override
// Authorize() and Validate() with fixed auth trimming.
func newFixedAuthPolicySession(tpm transport.TPM, auth []byte) (tpm2.Session, func() error, error) {
	sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16,
		tpm2.Auth(auth))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create policy session: %w", err)
	}

	return &fixedAuthPolicySession{inner: sess, auth: auth}, cleanup, nil
}

func (s *fixedAuthPolicySession) Init(tpm transport.TPM) error {
	return s.inner.Init(tpm)
}

func (s *fixedAuthPolicySession) CleanupFailure(tpm transport.TPM) error {
	return s.inner.CleanupFailure(tpm)
}

func (s *fixedAuthPolicySession) NonceTPM() tpm2.TPM2BNonce {
	return s.inner.NonceTPM()
}

func (s *fixedAuthPolicySession) NewNonceCaller() error {
	return s.inner.NewNonceCaller()
}

func (s *fixedAuthPolicySession) Handle() tpm2.TPMHandle {
	return s.inner.Handle()
}

func (s *fixedAuthPolicySession) IsEncryption() bool {
	return s.inner.IsEncryption()
}

func (s *fixedAuthPolicySession) IsDecryption() bool {
	return s.inner.IsDecryption()
}

func (s *fixedAuthPolicySession) Encrypt(parameter []byte) error {
	return s.inner.Encrypt(parameter)
}

func (s *fixedAuthPolicySession) Decrypt(parameter []byte) error {
	return s.inner.Decrypt(parameter)
}

// Authorize computes the authorization HMAC with correct auth value trimming.
// This overrides go-tpm's policySession.Authorize() which uses the buggy
// hmacKeyFromAuthValue function.
func (s *fixedAuthPolicySession) Authorize(cc tpm2.TPMCC, parms, addNonces []byte, names []tpm2.TPM2BName, authIndex int) (*tpm2.TPMSAuthCommand, error) {
	sessionKey, nonceCaller, attrs, err := getSessionInternals(s.inner)
	if err != nil {
		return nil, fmt.Errorf("fixedAuthPolicySession: %w", err)
	}

	hmacKey := computeFixedHMACKey(sessionKey, s.auth)

	cpHashDigest, err := computeCPHash(tpm2.TPMAlgSHA256, cc, names, parms)
	if err != nil {
		return nil, err
	}

	hmacDigest, err := computeAuthHMAC(tpm2.TPMAlgSHA256, hmacKey,
		cpHashDigest, nonceCaller, s.NonceTPM().Buffer, addNonces, attrs)
	if err != nil {
		return nil, err
	}

	return &tpm2.TPMSAuthCommand{
		Handle:        s.Handle(),
		Nonce:         tpm2.TPM2BNonce{Buffer: nonceCaller},
		Attributes:    attrs,
		Authorization: tpm2.TPM2BData{Buffer: hmacDigest},
	}, nil
}

// Validate validates the response HMAC with correct auth value trimming.
// This overrides go-tpm's policySession.Validate() which uses the buggy
// hmacKeyFromAuthValue function.
func (s *fixedAuthPolicySession) Validate(rc tpm2.TPMRC, cc tpm2.TPMCC, parms []byte, names []tpm2.TPM2BName, authIndex int, auth *tpm2.TPMSAuthResponse) error {
	sessionKey, nonceCaller, _, err := getSessionInternals(s.inner)
	if err != nil {
		return fmt.Errorf("fixedAuthPolicySession.Validate: %w", err)
	}

	hmacKey := computeFixedHMACKey(sessionKey, s.auth)

	rpHashDigest, err := computeRPHash(tpm2.TPMAlgSHA256, rc, cc, parms)
	if err != nil {
		return err
	}

	// For response validation: nonceNewer = nonceTPM, nonceOlder = nonceCaller
	mac, err := computeAuthHMAC(tpm2.TPMAlgSHA256, hmacKey,
		rpHashDigest, auth.Nonce.Buffer, nonceCaller, nil, auth.Attributes)
	if err != nil {
		return err
	}

	if !hmac.Equal(mac, auth.Authorization.Buffer) {
		return fmt.Errorf("incorrect authorization HMAC")
	}

	return nil
}

// computeFixedHMACKey computes the HMAC key with correct auth trimming.
// Key = sessionKey || fixedTrimAuth(auth)
func computeFixedHMACKey(sessionKey []byte, auth []byte) []byte {
	var hmacKey []byte
	hmacKey = append(hmacKey, sessionKey...)
	hmacKey = append(hmacKey, fixedTrimAuth(auth)...)
	return hmacKey
}

// getSessionInternals reads private fields from a go-tpm policy session
// using reflect. Returns sessionKey, nonceCaller, attrs.
func getSessionInternals(sess tpm2.Session) (sessionKey []byte, nonceCaller []byte, attrs tpm2.TPMASession, err error) {
	v := reflect.ValueOf(sess)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	sessionKeyField := v.FieldByName("sessionKey")
	if !sessionKeyField.IsValid() {
		return nil, nil, tpm2.TPMASession{}, fmt.Errorf("sessionKey field not found")
	}
	if sessionKeyField.Kind() == reflect.Slice && sessionKeyField.Len() > 0 {
		sessionKey = getBytesFromReflectSlice(sessionKeyField)
	}

	nonceCallerField := v.FieldByName("nonceCaller")
	if !nonceCallerField.IsValid() {
		return nil, nil, tpm2.TPMASession{}, fmt.Errorf("nonceCaller field not found")
	}
	bufField := nonceCallerField.FieldByName("Buffer")
	if bufField.IsValid() && bufField.Kind() == reflect.Slice && bufField.Len() > 0 {
		nonceCaller = getBytesFromReflectSlice(bufField)
	}

	attrsField := v.FieldByName("attrs")
	if !attrsField.IsValid() {
		return nil, nil, tpm2.TPMASession{}, fmt.Errorf("attrs field not found")
	}
	bitfieldField := attrsField.FieldByName("bitfield8")
	if bitfieldField.IsValid() {
		bfVal := uint8(bitfieldField.Uint())
		attrs = tpm2.TPMASession{}
		attrs.ContinueSession = bfVal&(1<<0) != 0
		attrs.AuditExclusive = bfVal&(1<<1) != 0
		attrs.AuditReset = bfVal&(1<<2) != 0
		attrs.Decrypt = bfVal&(1<<5) != 0
		attrs.Encrypt = bfVal&(1<<6) != 0
		attrs.Audit = bfVal&(1<<7) != 0
	} else {
		attrs = tpm2.TPMASession{}
		if f := attrsField.FieldByName("ContinueSession"); f.IsValid() {
			attrs.ContinueSession = f.Bool()
		}
		if f := attrsField.FieldByName("Decrypt"); f.IsValid() {
			attrs.Decrypt = f.Bool()
		}
		if f := attrsField.FieldByName("Encrypt"); f.IsValid() {
			attrs.Encrypt = f.Bool()
		}
		if f := attrsField.FieldByName("Audit"); f.IsValid() {
			attrs.Audit = f.Bool()
		}
	}

	return sessionKey, nonceCaller, attrs, nil
}

// getBytesFromReflectSlice reads bytes from an unexported []byte slice field.
func getBytesFromReflectSlice(v reflect.Value) []byte {
	if v.Kind() != reflect.Slice || v.Len() == 0 {
		return nil
	}
	readable := v.Slice(0, v.Len())
	result := make([]byte, readable.Len())
	copy(result, readable.Bytes())
	return result
}

// computeCPHash computes the TPM command parameter hash.
// cpHash = H(CC || names || parms)
func computeCPHash(alg tpm2.TPMIAlgHash, cc tpm2.TPMCC, names []tpm2.TPM2BName, parms []byte) ([]byte, error) {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, uint32(cc))
	for _, name := range names {
		h.Write(name.Buffer)
	}
	h.Write(parms)
	return h.Sum(nil), nil
}

// computeRPHash computes the TPM response parameter hash.
// rpHash = H(RC || CC || parms)
func computeRPHash(alg tpm2.TPMIAlgHash, rc tpm2.TPMRC, cc tpm2.TPMCC, parms []byte) ([]byte, error) {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, uint32(rc))
	binary.Write(h, binary.BigEndian, uint32(cc))
	h.Write(parms)
	return h.Sum(nil), nil
}

// computeAuthHMAC computes the authorization HMAC.
// HMAC = HMAC-SHA256(key, pHash || nonceNewer || nonceOlder || addNonces || attrs)
func computeAuthHMAC(alg tpm2.TPMIAlgHash, key []byte, pHash, nonceNewer, nonceOlder, addNonces []byte, attrs tpm2.TPMASession) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(pHash)
	mac.Write(nonceNewer)
	mac.Write(nonceOlder)
	mac.Write(addNonces)
	mac.Write(attrsToBytesFixed(attrs))
	return mac.Sum(nil), nil
}

// attrsToBytesFixed converts TPMASession to a byte (same as go-tpm's attrsToBytes).
func attrsToBytesFixed(attrs tpm2.TPMASession) []byte {
	var res byte
	if attrs.ContinueSession {
		res |= (1 << 0)
	}
	if attrs.AuditExclusive {
		res |= (1 << 1)
	}
	if attrs.AuditReset {
		res |= (1 << 2)
	}
	if attrs.Decrypt {
		res |= (1 << 5)
	}
	if attrs.Encrypt {
		res |= (1 << 6)
	}
	if attrs.Audit {
		res |= (1 << 7)
	}
	return []byte{res}
}
