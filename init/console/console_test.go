package console

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadEntryParsing drives the production line reader against a pipe.
// Echo itself is a kernel line-discipline behavior only visible on a real
// tty (echo does not happen on pipes); what is verified here is the input
// handling, and the echo contract is asserted in TestTermiosForEntry.
func TestReadEntryParsing(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain digits", "12345678\n", "12345678"},
		{"stops at carriage return", "12345678\r\n", "12345678"},
		{"keeps padding", "  12345678 \n", "  12345678 "},
		{"letters", "abcdef12\n", "abcdef12"},
		{"empty line", "\n", ""},
		{"unterminated", "12345678", "12345678"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			go func() {
				_, _ = w.WriteString(tc.input)
				w.Close()
			}()

			if got := readEntry(r, 4096); got != tc.want {
				t.Errorf("readEntry = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReadEntryLengthBound pins that an over-long line does not grow the
// buffer without limit.
func TestReadEntryLengthBound(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() {
		_, _ = w.WriteString(strings.Repeat("a", 100) + "\n")
		w.Close()
	}()

	if got := readEntry(r, 10); len(got) != 10 {
		t.Errorf("len(readEntry) = %d, want 10", len(got))
	}
}

// TestTermiosForEntry pins the echo contract of both entry paths:
// passphrases and PINs must not be echoed, one-time recovery codes must be.
// The bug this guards: reusing the passphrase termios edit for the HOTP
// prompt hid the digits the user typed.
func TestTermiosForEntry(t *testing.T) {
	const echoFlags = unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOPRT | unix.ECHOKE

	base := unix.Termios{Lflag: unix.ICANON | unix.ISIG | unix.IEXTEN}

	t.Run("code entry keeps echo", func(t *testing.T) {
		hidden := base
		hidden.Lflag &^= echoFlags
		got := termiosForEntry(&hidden, true)
		if got.Lflag&unix.ECHO == 0 {
			t.Error("ReadCode leaves ECHO disabled — typed digits stay invisible")
		}
		if got.Lflag&unix.ICANON == 0 {
			t.Error("canonical mode must stay enabled for line editing")
		}
	})

	t.Run("passphrase entry clears every echo flag", func(t *testing.T) {
		loud := base
		loud.Lflag |= echoFlags
		got := termiosForEntry(&loud, false)
		if got.Lflag&echoFlags != 0 {
			t.Errorf("echo flags remain set: 0x%x", got.Lflag&echoFlags)
		}
	})

	t.Run("the original state is not modified", func(t *testing.T) {
		orig := base
		before := orig.Lflag
		_ = termiosForEntry(&orig, true)
		if orig.Lflag != before {
			t.Error("termiosForEntry modified its input")
		}
	})
}

// TestWaitEnterTimesOut pins that the wait is bounded: with no console input
// the function must return instead of blocking PID 1 forever.
func TestWaitEnterTimesOut(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	start := time.Now()
	waitEnter(int(r.Fd()), 100*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("waitEnter took %v, want roughly 100ms", elapsed)
	}
}

// TestWaitEnterReturnsOnEnter pins that pressing Enter ends the wait
// immediately, without waiting for the timeout.
func TestWaitEnterReturnsOnEnter(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	if _, err := w.WriteString("\n"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	waitEnter(int(r.Fd()), 10*time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waitEnter took %v although Enter was available", elapsed)
	}
}

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
