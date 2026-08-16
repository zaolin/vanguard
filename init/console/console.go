package console

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var consoleFd *os.File

// DebugEnabled controls whether DebugPrint outputs anything.
// Set this from main.go based on the debug build tag.
var DebugEnabled bool

// TUIActive is set to true when the TUI is running to suppress direct console output.
// This prevents console output from interfering with bubbletea's alt screen.
var TUIActive bool

// LogFunc is a callback for boot logging - will be set by the main init package.
// All console output (Print and DebugPrint) will be sent to this function.
var LogFunc func(message string) = func(message string) {}

// Setup initializes the console for early output
func Setup() error {
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
	if !TUIActive {
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
	if consoleFd != nil && !TUIActive {
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
	if consoleFd != nil && !TUIActive {
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
	newState := *oldState
	newState.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOPRT | unix.ECHOKE
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &newState); err != nil {
		return "", fmt.Errorf("failed to disable echo: %w", err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, oldState)

	// Read password (max 4KB to prevent memory exhaustion)
	const maxPasswordLen = 4096
	var password []byte
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == '\n' || buf[0] == '\r' {
			break
		}
		if len(password) >= maxPasswordLen {
			continue
		}
		password = append(password, buf[0])
	}
	// Zero the read buffer
	buf[0] = 0
	fmt.Fprint(f, "\n")

	return string(password), nil
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
