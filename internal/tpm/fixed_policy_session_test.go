package tpm

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestFixedTrimAuth_NoTrailingZeros(t *testing.T) {
	auth := []byte{0x5b, 0xfe, 0xf0, 0x05, 0xd8, 0x72, 0xe1, 0x6a}
	got := fixedTrimAuth(auth)
	if !bytes.Equal(got, auth) {
		t.Errorf("fixedTrimAuth should not modify value with no trailing zeros: got %x, want %x", got, auth)
	}
}

func TestFixedTrimAuth_TrailingZeros(t *testing.T) {
	auth := []byte{0x5b, 0xfe, 0xf0, 0x00, 0x00}
	want := []byte{0x5b, 0xfe, 0xf0}
	got := fixedTrimAuth(auth)
	if !bytes.Equal(got, want) {
		t.Errorf("fixedTrimAuth should trim trailing zeros: got %x, want %x", got, want)
	}
}

func TestFixedTrimAuth_NonTrailingZero(t *testing.T) {
	auth := []byte{0x5b, 0xfe, 0xf0, 0x00, 0xd8, 0x72, 0xe1, 0x6a}
	got := fixedTrimAuth(auth)
	if !bytes.Equal(got, auth) {
		t.Errorf("fixedTrimAuth should NOT trim non-trailing zeros: got %x, want %x", got, auth)
	}
}

func TestFixedTrimAuth_NonTrailingZeroFollowedByTrailingZeros(t *testing.T) {
	auth := []byte{0x5b, 0xfe, 0xf0, 0x00, 0xd8, 0x72, 0x00, 0x00}
	want := []byte{0x5b, 0xfe, 0xf0, 0x00, 0xd8, 0x72}
	got := fixedTrimAuth(auth)
	if !bytes.Equal(got, want) {
		t.Errorf("fixedTrimAuth should trim only trailing zeros: got %x, want %x", got, want)
	}
}

func TestFixedTrimAuth_AllZeros(t *testing.T) {
	auth := []byte{0x00, 0x00, 0x00}
	got := fixedTrimAuth(auth)
	if len(got) != 0 {
		t.Errorf("fixedTrimAuth should return empty for all-zeros: got %x", got)
	}
}

func TestFixedTrimAuth_Empty(t *testing.T) {
	got := fixedTrimAuth(nil)
	if len(got) != 0 {
		t.Errorf("fixedTrimAuth should return empty for nil: got %x", got)
	}
}

func TestFixedTrimAuth_SingleNonZeroByte(t *testing.T) {
	auth := []byte{0x42}
	got := fixedTrimAuth(auth)
	if !bytes.Equal(got, auth) {
		t.Errorf("fixedTrimAuth should not modify single non-zero byte: got %x, want %x", got, auth)
	}
}

func TestFixedTrimAuth_SingleZeroByte(t *testing.T) {
	auth := []byte{0x00}
	got := fixedTrimAuth(auth)
	if len(got) != 0 {
		t.Errorf("fixedTrimAuth should trim single zero: got %x", got)
	}
}

func TestBuggyHmacKeyFromAuthValue(t *testing.T) {
	buggy := func(auth []byte) []byte {
		key := make([]byte, len(auth))
		copy(key, auth)
		for i := len(key) - 1; i >= 0; i-- {
			if key[i] == 0 {
				key = key[:i]
			}
		}
		return key
	}

	tests := []struct {
		name    string
		auth    []byte
		buggyW  []byte
		fixedW  []byte
		differs bool
	}{
		{
			name:   "no zeros",
			auth:   []byte{0x5b, 0xfe, 0xf0, 0x05},
			buggyW: []byte{0x5b, 0xfe, 0xf0, 0x05},
			fixedW: []byte{0x5b, 0xfe, 0xf0, 0x05},
		},
		{
			name:   "trailing zeros only",
			auth:   []byte{0x5b, 0xfe, 0xf0, 0x00, 0x00},
			buggyW: []byte{0x5b, 0xfe, 0xf0},
			fixedW: []byte{0x5b, 0xfe, 0xf0},
		},
		{
			name:    "non-trailing zero",
			auth:    []byte{0x5b, 0xfe, 0xf0, 0x00, 0xd8, 0x72, 0xe1, 0x6a},
			buggyW:  []byte{0x5b, 0xfe, 0xf0},
			fixedW:  []byte{0x5b, 0xfe, 0xf0, 0x00, 0xd8, 0x72, 0xe1, 0x6a},
			differs: true,
		},
		{
			name:    "zero then non-zero then trailing zeros",
			auth:    []byte{0x5b, 0x00, 0xd8, 0x00, 0x00},
			buggyW:  []byte{0x5b},
			fixedW:  []byte{0x5b, 0x00, 0xd8},
			differs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buggyResult := buggy(tt.auth)
			fixedResult := fixedTrimAuth(tt.auth)

			if !bytes.Equal(buggyResult, tt.buggyW) {
				t.Errorf("buggy function: got %x, want %x", buggyResult, tt.buggyW)
			}
			if !bytes.Equal(fixedResult, tt.fixedW) {
				t.Errorf("fixed function: got %x, want %x", fixedResult, tt.fixedW)
			}
			if tt.differs {
				if bytes.Equal(buggyResult, fixedResult) {
					t.Errorf("expected buggy and fixed to differ, but they match: %x", buggyResult)
				}
			}
		})
	}
}

func TestAttrsToBytesFixed(t *testing.T) {
	attrs := tpm2TPMASessionContinueOnly()
	got := attrsToBytesFixed(attrs)
	if got[0] != 0x01 {
		t.Errorf("attrsToBytesFixed for ContinueSession: got 0x%02x, want 0x01", got[0])
	}
}

func tpm2TPMASessionContinueOnly() tpm2.TPMASession {
	// Can't construct TPMASession directly due to bitfield8 embedding.
	// Use the go-tpm API by creating a session and reading its attrs.
	return tpm2.TPMASession{
		ContinueSession: true,
	}
}
