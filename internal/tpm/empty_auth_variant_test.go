package tpm

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestEmptyAuthVariantCannotRescuePolicyAuthValueTokens pins why the pcrlock
// unseal loop skips the "empty" auth variant after a rejected auth value.
//
// The sealed object's policy digest is computed from the session commands.
// The PIN variant runs PolicyAuthValue, the empty variant does not — so the
// two variants produce DIFFERENT policy digests and only one of them can
// match the object's authPolicy. When the TPM reports AUTH_FAIL, the policy
// digest has already matched (otherwise the failure would be POLICY_FAIL),
// which means the object was sealed WITH PolicyAuthValue. A variant that
// omits that command therefore cannot succeed, whatever the object's auth
// value is — including the empty one.
//
// The test uses an object with an EMPTY auth value, which is the case the
// empty variant is sometimes assumed to rescue: it does not. What works is
// an empty PIN through the PIN variant.
func TestEmptyAuthVariantCannotRescuePolicyAuthValueTokens(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	srk, srkCleanup, err := client.createSRK(tpmTransport, "ecc")
	if err != nil {
		t.Fatal(err)
	}
	defer srkCleanup()

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	authPolicy, err := computePolicyAuthValueHash(make([]byte, 32))
	if err != nil {
		t.Fatalf("computePolicyAuthValueHash: %v", err)
	}

	// Sealed WITH PolicyAuthValue in its policy but with an EMPTY auth
	// value: a token that declares a PIN yet was sealed without one.
	priv, pub := sealDataWithPolicy(t, tpmTransport, srk, secret, []byte{}, authPolicy)
	loadRsp := loadData(t, tpmTransport, srk, priv, pub)

	// A wrong non-empty PIN: the policy digest matches, the auth value is
	// rejected -> AUTH_FAIL. This is the point where the loop skips the
	// empty variant.
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
		t.Fatal("unseal with a wrong PIN unexpectedly succeeded")
	}
	if !isAuthValueRejected(wrongErr) {
		t.Fatalf("wrong PIN did not produce an auth rejection: %v", wrongErr)
	}

	// The empty variant (no PolicyAuthValue) cannot succeed: its policy
	// digest differs from the object's authPolicy.
	emptySess, emptyCleanup, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		t.Fatal(err)
	}
	_, emptyErr := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   emptySess,
	}}).Execute(tpmTransport)
	emptyCleanup()
	if emptyErr == nil {
		t.Fatal("the empty auth variant unexpectedly succeeded — skipping it after AUTH_FAIL would be wrong")
	}
	if isAuthValueRejected(emptyErr) {
		t.Errorf("the empty variant should fail the policy check, not the auth check: %v", emptyErr)
	}

	// What DOES work for such a token is an empty PIN through the PIN
	// variant (PolicyAuthValue included).
	emptyPINSess, emptyPINCleanup, err := newFixedAuthPolicySession(tpmTransport, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.PolicyAuthValue{PolicySession: emptyPINSess.Handle()}).Execute(tpmTransport); err != nil {
		t.Fatal(err)
	}
	unsealed, err := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   emptyPINSess,
	}}).Execute(tpmTransport)
	emptyPINCleanup()
	if err != nil {
		t.Fatalf("an empty PIN through the PIN variant failed: %v", err)
	}
	if len(unsealed.OutData.Buffer) != len(secret) {
		t.Errorf("unsealed %d bytes, want %d", len(unsealed.OutData.Buffer), len(secret))
	}
}
