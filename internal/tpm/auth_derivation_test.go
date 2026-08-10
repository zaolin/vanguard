package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestDerivePinAuthSaltedVersusUnsalted(t *testing.T) {
	pin := "test"
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	salted := DerivePinAuthSalted(pin, salt)
	unsalted := DerivePinAuthUnseal(pin)

	if len(salted) == 0 {
		t.Error("salted auth value is empty")
	}
	if len(unsalted) == 0 {
		t.Error("unsalted auth value is empty")
	}
	if bytes.Equal(salted, unsalted) {
		t.Error("salted and unsalted auth values should differ")
	}
}

func TestDerivePinAuthSaltedDerivationChain(t *testing.T) {
	pin := "mypin"
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	pbkdf2Key := pbkdf2.Key([]byte(pin), salt, 10000, sha256.Size, sha256.New)
	b64String := base64.StdEncoding.EncodeToString(pbkdf2Key)
	expectedHash := sha256.Sum256([]byte(b64String))
	expected := bytes.TrimRight(expectedHash[:], "\x00")

	got := DerivePinAuthSalted(pin, salt)

	if !bytes.Equal(got, expected) {
		t.Errorf("DerivePinAuthSalted = %x, want %x", got, expected)
	}
}

func TestDerivePinAuthUnsealNoSalt(t *testing.T) {
	pin := "mypin"
	hash := sha256.Sum256([]byte(pin))
	expected := bytes.TrimRight(hash[:], "\x00")

	got := DerivePinAuthUnseal(pin)

	if !bytes.Equal(got, expected) {
		t.Errorf("DerivePinAuthUnseal = %x, want %x", got, expected)
	}
}

func TestDerivePinAuthSaltedWith44ByteSalt(t *testing.T) {
	pin := "1234"
	salt := make([]byte, 44)
	for i := range salt {
		salt[i] = byte(i + 0xA0)
	}

	got := DerivePinAuthSalted(pin, salt)

	pbkdf2Key := pbkdf2.Key([]byte(pin), salt, 10000, sha256.Size, sha256.New)
	b64String := base64.StdEncoding.EncodeToString(pbkdf2Key)
	expectedHash := sha256.Sum256([]byte(b64String))
	expected := bytes.TrimRight(expectedHash[:], "\x00")

	if !bytes.Equal(got, expected) {
		t.Errorf("DerivePinAuthSalted with 44-byte salt = %x, want %x", got, expected)
	}
}

func TestDerivePinAuthSaltedTrimTrailingZeros(t *testing.T) {
	pin := "test"
	salt := make([]byte, 44)

	got := DerivePinAuthSalted(pin, salt)

	if len(got) > 0 && got[len(got)-1] == 0 {
		t.Error("DerivePinAuthSalted should trim trailing zeros")
	}
}

func TestDerivePinAuthUnsealTrimTrailingZeros(t *testing.T) {
	pin := "test"

	got := DerivePinAuthUnseal(pin)

	if len(got) > 0 && got[len(got)-1] == 0 {
		t.Error("DerivePinAuthUnseal should trim trailing zeros")
	}
}
