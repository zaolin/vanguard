package console

import "testing"

func TestZeroString(t *testing.T) {
	s := "secret passphrase data"
	ZeroString(&s)
	for i := range s {
		if s[i] != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, s[i])
		}
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 0xFF}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, v)
		}
	}
}

func TestZeroBytesEmpty(t *testing.T) {
	ZeroBytes([]byte{}) // should not panic
}

func TestZeroStringEmpty(t *testing.T) {
	s := ""
	ZeroString(&s) // should not panic
}