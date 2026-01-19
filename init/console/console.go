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
			_ = unix.Dup2(int(fd.Fd()), 1)
			_ = unix.Dup2(int(fd.Fd()), 2)
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

// ReadPassword reads a password from console with echo disabled
func ReadPassword(prompt string) (string, error) {
	if consoleFd == nil {
		return "", fmt.Errorf("console not initialized")
	}

	Print("%s", prompt)

	// Get current terminal settings
	oldState, err := unix.IoctlGetTermios(int(consoleFd.Fd()), unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("failed to get terminal state: %w", err)
	}

	// Disable echo
	newState := *oldState
	newState.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(consoleFd.Fd()), unix.TCSETS, &newState); err != nil {
		return "", fmt.Errorf("failed to disable echo: %w", err)
	}
	defer unix.IoctlSetTermios(int(consoleFd.Fd()), unix.TCSETS, oldState)

	// Read password
	var password []byte
	buf := make([]byte, 1)
	for {
		n, err := consoleFd.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == '\n' || buf[0] == '\r' {
			break
		}
		password = append(password, buf[0])
	}
	Print("\n")

	return string(password), nil
}
