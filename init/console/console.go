package console

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var consoleFd *os.File

// DebugEnabled controls whether DebugPrint outputs anything.
// Set this from main.go based on the debug build tag.
var DebugEnabled bool

// tuiActive records whether the TUI is running, to suppress direct console
// output. The TUI sets it from its own goroutine while console output happens
// on others, so the state must be atomic — a plain bool is a data race.
var tuiActive atomic.Bool

// SetTUIActive records whether the TUI currently owns the console.
func SetTUIActive(active bool) {
	tuiActive.Store(active)
}

// TUIActive reports whether the TUI is running. Console output is suppressed
// while it is, to avoid interfering with bubbletea's alt screen.
func TUIActive() bool {
	return tuiActive.Load()
}

// LogFunc is a callback for boot logging - will be set by the main init package.
// All console output (Print and DebugPrint) will be sent to this function.
var LogFunc func(message string) = func(message string) {}

// Setup initializes the console for early output
func Setup() error {
	// Ensure /dev/console exists as char device (5,1). The generated
	// initramfs carries device nodes, but if the archive was produced by an
	// older vanguard (broken rdev serialization → node (0,0)) or the kernel
	// did not mount devtmpfs before /init, the open below would fail and
	// boot would halt with no output at all. Mknod is a cheap no-op when
	// the node already exists with the right type.
	mknodConsole()

	// Try various console devices
	for _, path := range []string{"/dev/console", "/dev/tty1", "/dev/ttyS0"} {
		fd, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			consoleFd = fd
			// Redirect stdout/stderr to console
			if err := unix.Dup2(int(fd.Fd()), 1); err != nil {
				fmt.Fprintf(fd, "warning: failed to redirect stdout: %v\n", err)
			}
			if err := unix.Dup2(int(fd.Fd()), 2); err != nil {
				fmt.Fprintf(fd, "warning: failed to redirect stderr: %v\n", err)
			}
			return nil
		}
	}
	return fmt.Errorf("no console device available")
}

// mknodConsole creates /dev/console (char 5:1) and /dev/null (char 1:3) as
// a last-resort fallback. Errors are ignored: on a correctly-built
// initramfs (or devtmpfs) the nodes already exist, and there is nothing
// further to do if creation fails.
func mknodConsole() {
	// glibc/linux makedev for small numbers: (major << 8 | minor).
	_ = unix.Mknod("/dev/console", unix.S_IFCHR|0600, int(uint32(5)<<8|uint32(1)))
	_ = unix.Mknod("/dev/null", unix.S_IFCHR|0666, int(uint32(1)<<8|uint32(3)))
}

// SuppressKernelMessages sets the kernel console log level to suppress
// kernel messages (dmesg) from appearing on the console.
// This prevents kernel messages from interfering with password prompts.
func SuppressKernelMessages() {
	// Write to /proc/sys/kernel/printk to set console log level
	// Format: console_loglevel default_message_loglevel minimum_console_loglevel default_console_loglevel
	// Setting first value to 0 suppresses all kernel messages
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("0"), 0644)
}

// RestoreKernelMessages restores the default kernel console log level
func RestoreKernelMessages() {
	// Restore to level 4 (KERN_WARNING and above)
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("4"), 0644)
}

// SuppressStderr redirects stderr to /dev/null to prevent external commands
// (like tpm2-tss library) from corrupting the TUI display.
// Returns a function to restore stderr. Call this before exec.Command.Run().
func SuppressStderr() func() {
	if !TUIActive() {
		return func() {}
	}

	// Save current stderr fd
	savedStderr, err := unix.Dup(2)
	if err != nil {
		return func() {}
	}

	// Open /dev/null and redirect stderr to it
	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		unix.Close(savedStderr)
		return func() {}
	}
	_ = unix.Dup2(int(devNull.Fd()), 2)
	devNull.Close()

	return func() {
		_ = unix.Dup2(savedStderr, 2)
		unix.Close(savedStderr)
	}
}

// Print outputs to the early console (suppressed when TUI is active)
func Print(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	// Skip console output when TUI is active to avoid interfering with alt screen
	if consoleFd != nil && !TUIActive() {
		fmt.Fprint(consoleFd, msg)
	}
	LogFunc(msg)
}

// DebugPrint outputs to the console only when DebugEnabled is true.
// Use this for informational/verbose messages that should not appear
// in production builds. Also suppressed when TUI is active.
func DebugPrint(format string, args ...interface{}) {
	if !DebugEnabled {
		return
	}
	msg := fmt.Sprintf(format, args...)
	// Skip console output when TUI is active to avoid interfering with alt screen
	if consoleFd != nil && !TUIActive() {
		fmt.Fprint(consoleFd, msg)
	}
	LogFunc(msg)
}

// ReadPassword reads a password from console with echo disabled.
// It re-opens the console device fresh to avoid conflicts with any
// lingering TUI goroutine that may still hold the original consoleFd
// input reader (bubbletea uses /dev/tty for input).
func ReadPassword(prompt string) (string, error) {
	// Re-open the console device fresh. This ensures we get a clean
	// file descriptor that isn't shared with the TUI's input reader.
	// If the TUI goroutine is still reading from the old fd, our new
	// fd will receive input independently.
	f, err := os.OpenFile("/dev/console", os.O_RDWR, 0)
	if err != nil {
		// Fallback to the shared consoleFd
		if consoleFd == nil {
			return "", fmt.Errorf("console not initialized")
		}
		f = consoleFd
	} else {
		defer f.Close()
	}

	// Print prompt directly to the fd
	fmt.Fprint(f, prompt)

	// Get current terminal settings
	fd := int(f.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("failed to get terminal state: %w", err)
	}

	// Disable echo and related echo flags to prevent password keystroke leakage
	newState := termiosForEntry(oldState, false)
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, newState); err != nil {
		return "", fmt.Errorf("failed to disable echo: %w", err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, oldState)

	// Read password (max 4KB to prevent memory exhaustion)
	const maxPasswordLen = 4096
	password := readEntry(f, maxPasswordLen)
	fmt.Fprint(f, "\n")

	return password, nil
}

// termiosForEntry returns the terminal state to use while reading an entry.
// With echo false every echo flag is cleared (passphrases, PINs); with echo
// true ECHO is set (one-time recovery codes). Canonical mode is left
// untouched so the kernel line discipline handles erase and delivers the
// line on Enter.
func termiosForEntry(old *unix.Termios, echo bool) *unix.Termios {
	state := *old
	if echo {
		state.Lflag |= unix.ECHO
	} else {
		state.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOPRT | unix.ECHOKE
	}
	return &state
}

// readEntry reads one line from f, up to maxLen bytes, stopping at the line
// ending. The read buffer is zeroed afterwards.
func readEntry(f *os.File, maxLen int) string {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == '\n' || buf[0] == '\r' {
			break
		}
		if len(line) >= maxLen {
			continue
		}
		line = append(line, buf[0])
	}
	buf[0] = 0
	return string(line)
}

// ReadCode reads a fixed-length, non-secret entry code (e.g. the HOTP
// recovery code) from the console WITH echo. Unlike passphrases, these
// codes are one-time values that gate a second factor; hiding them makes
// typos and wrong-keymap input impossible to diagnose. The terminal is
// left in canonical mode, so the line discipline handles backspace.
func ReadCode(prompt string) (string, error) {
	f, err := os.OpenFile("/dev/console", os.O_RDWR, 0)
	if err != nil {
		if consoleFd == nil {
			return "", fmt.Errorf("console not initialized")
		}
		f = consoleFd
	} else {
		defer f.Close()
	}

	fmt.Fprint(f, prompt)

	fd := int(f.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("failed to get terminal state: %w", err)
	}
	// Ensure echo is on (cheap no-op when it already is). Canonical mode
	// is left untouched — the kernel buffers the line and delivers it on
	// Enter, including local erase handling.
	newState := termiosForEntry(oldState, true)
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, newState); err != nil {
		return "", fmt.Errorf("failed to enable echo: %w", err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, oldState)

	const maxCodeLen = 4096
	line := readEntry(f, maxCodeLen)
	fmt.Fprint(f, "\n")

	return strings.TrimSpace(line), nil
}

// WaitEnterTimeout bounds how long WaitEnter waits for the user to press
// Enter. An unattended boot (serial console without a reader, a VM with no
// console) must not hang forever in PID 1 — the error message stays on
// screen for the timeout, then the boot continues to its halt path.
const WaitEnterTimeout = 30 * time.Second

// WaitEnter waits until the user presses Enter on the console or the
// timeout expires. Used on fatal failure paths so the error stays on
// screen until the user has read it (errors that vanish in under a second
// are unreadable).
//
// The wait is bounded: an unattended boot (a serial console without a
// reader, a VM with no console) must not hang forever in PID 1. Polling
// with a deadline bounds the wait without leaking a goroutine or leaving a
// read pending on a descriptor that is about to be closed.
func WaitEnter() {
	if fd, err := unix.Open("/dev/console", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err == nil {
		defer unix.Close(fd)
		waitEnter(fd, WaitEnterTimeout)
		return
	}
	if consoleFd != nil {
		// Fallback: the shared console descriptor. It must not be closed
		// here — other console functions keep using it.
		waitEnter(int(consoleFd.Fd()), WaitEnterTimeout)
	}
}

// waitEnter polls fd for Enter until timeout expires. Non-Enter input is
// drained so a stray keypress does not terminate the wait.
func waitEnter(fd int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(remaining.Milliseconds()))
		if err != nil || n == 0 {
			// Timeout or error: the boot continues to its halt path.
			return
		}
		var buf [1]byte
		nread, err := unix.Read(fd, buf[:])
		if err != nil || nread == 0 {
			return
		}
		if buf[0] == '\n' || buf[0] == '\r' {
			return
		}
	}
}

// ZeroString converts a string to a mutable byte slice, zeroes it, and returns
// the empty string. This is best-effort: Go strings are immutable, so the
// original backing array may have been copied by the runtime. Still, this
// reduces the cold-boot extraction window for the most common code path where
// the string's backing array is the same slice that was read.
func ZeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// ZeroBytes zeroes a byte slice in place.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
