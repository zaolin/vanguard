package tpm

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestDACounterSemantics pins the dictionary-attack behaviour that the
// pcrlock unseal path depends on:
//
//   - A rejected auth value (wrong PIN) increments the DA counter — this
//     is the attempt the user must be allowed to retry.
//   - A failure on the policy check (e.g. no auth value supplied where the
//     object requires one) does NOT increment it — the TPM fails the
//     policy before the auth check.
//
// The second fact is why the "empty auth" fallback variant does not burn
// a lockout slot, and why it is skipped after an AUTH_FAIL anyway (it
// could never succeed and only costs a TPM round-trip).
func TestDACounterSemantics(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	srk, srkCleanup, err := client.createSRK(tpmTransport, "ecc")
	if err != nil {
		t.Fatal(err)
	}
	defer srkCleanup()

	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i)
	}
	correctAuth := []byte("correctpin")
	authPolicy, err := computePolicyAuthValueHash(make([]byte, 32))
	if err != nil {
		t.Fatalf("computePolicyAuthValueHash: %v", err)
	}
	priv, pub := sealDataWithPolicy(t, tpmTransport, srk, secret, correctAuth, authPolicy)
	loadRsp := loadData(t, tpmTransport, srk, priv, pub)

	readCounter := func() uint64 {
		st, err := client.GetLockoutStatus()
		if err != nil {
			t.Fatal(err)
		}
		return st.LockoutCounter
	}

	before := readCounter()

	// Wrong auth value -> AUTH_FAIL, DA counter incremented.
	sess, sessCleanup, err := newFixedAuthPolicySession(tpmTransport, []byte("wrongpin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.PolicyAuthValue{PolicySession: sess.Handle()}).Execute(tpmTransport); err != nil {
		t.Fatal(err)
	}
	_, wrongErr := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   sess,
	}}).Execute(tpmTransport)
	sessCleanup()
	if wrongErr == nil {
		t.Fatal("unseal with wrong auth unexpectedly succeeded")
	}
	if !isAuthValueRejected(wrongErr) {
		t.Errorf("wrong-auth error not recognized as an auth rejection: %v", wrongErr)
	}
	afterWrong := readCounter()
	if afterWrong <= before {
		t.Errorf("DA counter not incremented after a rejected auth value (%d -> %d)", before, afterWrong)
	}

	// No auth value -> POLICY_FAIL, DA counter NOT incremented.
	sess2, sess2Cleanup, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		t.Fatal(err)
	}
	_, noAuthErr := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   sess2,
	}}).Execute(tpmTransport)
	sess2Cleanup()
	if noAuthErr == nil {
		t.Fatal("unseal without auth unexpectedly succeeded")
	}
	if isAuthValueRejected(noAuthErr) {
		t.Errorf("policy failure misclassified as an auth rejection: %v", noAuthErr)
	}
	afterNoAuth := readCounter()
	if afterNoAuth != afterWrong {
		t.Errorf("DA counter changed on a policy failure (%d -> %d); the empty-auth fallback would consume a lockout slot",
			afterWrong, afterNoAuth)
	}
}

// TestIsAuthValueRejected pins the classifier used to decide whether the
// "empty auth" fallback variant is worth trying.
func TestIsAuthValueRejected(t *testing.T) {
	rejected := []error{
		errors.New("TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed"),
		errors.New("TPM_RC_BAD_AUTH"),
		errors.New("HMAC check failed"),
	}
	for _, err := range rejected {
		if !isAuthValueRejected(err) {
			t.Errorf("isAuthValueRejected(%v) = false, want true", err)
		}
	}

	notRejected := []error{
		errors.New("TPM_RC_POLICY_FAIL (session 1): a policy check failed"),
		errors.New("TPM_RC_INTEGRITY"),
	}
	for _, err := range notRejected {
		if isAuthValueRejected(err) {
			t.Errorf("isAuthValueRejected(%v) = true, want false", err)
		}
	}
}
