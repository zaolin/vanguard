//go:build !debug

package tui

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zaolin/vanguard/init/console"
)

// Boot stage names
const (
	StageConsole    = "Initializing console"
	StageMounting   = "Mounting filesystems"
	StageVConsole   = "Configuring vconsole"
	StageUdev       = "Starting udev"
	StageModules    = "Loading kernel modules"
	StageTPM        = "Loading TPM modules"
	StagePCRLock    = "Setting up pcrlock"
	StageLUKS       = "Unlocking encrypted devices"
	StageLVM        = "Activating LVM volumes"
	StageResume     = "Checking hibernate resume"
	StageRoot       = "Mounting root filesystem"
	StageFsck       = "Checking filesystem"
	StageSwitchroot = "Switching to root"
)

// maxPromptAttempts mirrors luks.MaxPINAttempts (3) for the on-screen
// attempt counter. Kept here because the TUI package cannot import luks
// (luks imports tui).
const maxPromptAttempts = 3

// Styles
var (
	stageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	promptStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))
)

// Model represents the boot TUI state
type Model struct {
	spinner spinner.Model
	stage   string
	stages  []stageEntry
	done    bool
	err     error

	// Password prompt mode
	passwordMode  bool
	passwordInput textinput.Model
	deviceName    string
	attempts      int
	passwordErr   string
	passwordDone  chan string

	// TPM lockout state
	lockedOut       bool
	lockoutMessage  string
	lockoutRecovery string

	// Standalone TPM error (PCR mismatch, token failure) — shown outside
	// password mode, e.g. before HOTP recovery takes over the console.
	tpmError string

	// Window dimensions
	width  int
	height int
}

type stageEntry struct {
	name   string
	status string // "running", "done", "error"
}

// PasswordResult is the result of password input
type PasswordResult struct {
	Password string
	Err      error
}

// Messages
type StageMsg string
type StageDoneMsg string
type StageErrorMsg struct {
	Stage string
	Err   error
}
type PasswordPromptMsg struct {
	Device string
	Done   chan string
}
type PasswordErrorMsg string
type PasswordErrorWithRetryMsg struct {
	Message string
	Done    chan string
}
type PasswordPromptDoneMsg struct{} // Signals password entry is complete
type TPMLockoutMsg struct {
	Message      string
	RecoveryHint string
}
type TPMErrorMsg struct {
	Message string
}
type QuitMsg struct{}

// ... (existing helper types) ...

// New creates a new boot TUI model
func New() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))

	ti := textinput.New()
	ti.Placeholder = ""
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.Width = 40

	return Model{
		spinner:       s,
		stage:         "",
		stages:        []stageEntry{},
		passwordInput: ti,
		passwordDone:  nil,
		width:         80, // Default width
		height:        24, // Default height
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if m.passwordMode {
			switch msg.Type {
			case tea.KeyEnter, tea.KeyCtrlJ:
				password := m.passwordInput.Value()
				// Sanitize password to remove any potential newline/CR characters
				// We do NOT use TrimSpace as passphrases may strictly contain spaces
				password = strings.TrimRight(password, "\r\n")
				m.passwordInput.SetValue("")
				if m.passwordDone != nil {
					m.passwordDone <- password
					m.passwordDone = nil
				}
				// Keep passwordMode=true - wait for explicit PasswordPromptDoneMsg or new prompt
				// This allows error messages to be displayed before the next prompt
				return m, nil
			case tea.KeyCtrlC:
				// Send empty string to unblock PromptPassword before quitting
				if m.passwordDone != nil {
					m.passwordDone <- ""
					m.passwordDone = nil
				}
				return m, tea.Quit
			}
			var cmd tea.Cmd
			m.passwordInput, cmd = m.passwordInput.Update(msg)
			cmds = append(cmds, cmd)
		} else {
			switch msg.String() {
			case "ctrl+c", "q":
				return m, tea.Quit
			}
		}

	case StageMsg:
		m.stage = string(msg)
		// Add to stages list if not already there
		found := false
		for i := range m.stages {
			if m.stages[i].name == string(msg) {
				m.stages[i].status = "running"
				found = true
				break
			}
		}
		if !found {
			m.stages = append(m.stages, stageEntry{name: string(msg), status: "running"})
		}

	case StageDoneMsg:
		for i := range m.stages {
			if m.stages[i].name == string(msg) {
				m.stages[i].status = "done"
				break
			}
		}

	case StageErrorMsg:
		m.err = msg.Err
		for i := range m.stages {
			if m.stages[i].name == msg.Stage {
				m.stages[i].status = "error"
				break
			}
		}

	case PasswordPromptMsg:
		// Reset state if this is a different device
		if m.deviceName != msg.Device {
			m.attempts = 0
			m.passwordErr = ""
		}
		m.passwordMode = true
		m.lockedOut = false
		m.tpmError = ""
		m.deviceName = msg.Device
		m.passwordDone = msg.Done
		m.passwordInput.Reset()
		m.passwordInput.Focus()
		return m, textinput.Blink

	case PasswordErrorMsg:
		m.passwordErr = string(msg)
		m.attempts++
		// Re-enable input for next attempt (but no channel - use PasswordErrorWithRetryMsg for retries)
		m.passwordInput.Reset()
		m.passwordInput.Focus()
		return m, textinput.Blink

	case PasswordErrorWithRetryMsg:
		// Error with retry - set up new channel for next attempt
		m.passwordErr = msg.Message
		m.attempts++
		m.passwordMode = true
		m.passwordDone = msg.Done
		m.passwordInput.Reset()
		m.passwordInput.Focus()
		return m, textinput.Blink

	case PasswordPromptDoneMsg:
		// Explicitly end password mode
		m.passwordMode = false
		m.passwordErr = ""
		m.attempts = 0

	case TPMLockoutMsg:
		// Show lockout message without password prompt
		m.passwordMode = false
		m.passwordErr = ""
		m.lockedOut = true
		m.lockoutMessage = msg.Message
		m.lockoutRecovery = msg.RecoveryHint

	case TPMErrorMsg:
		// Show TPM error (PCR mismatch, token failure) outside password
		// mode. The TUI stays up; the caller dwells so the reason is
		// readable before tearing the TUI down.
		m.passwordMode = false
		m.passwordErr = ""
		m.tpmError = msg.Message

	case QuitMsg:
		m.done = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model
func (m Model) View() string {
	// Use fallback dimensions if window size is not yet detected
	width := m.width
	if width == 0 {
		width = 80
	}
	height := m.height
	if height == 0 {
		height = 24
	}

	const clearLine = "\033[2K"

	// 1. Logo
	// Logo is embedded ANSI art. We wrap it in a style to center it if needed,
	// but since it's a fixed block, we can just treat it as a string.
	// We use lipgloss.JoinVertical to stack elements.

	// 2. Title
	// 2. Title
	// Title is now embedded ANSI art generated from Exo 2 font
	title := Title

	// 3. Main Content
	var mainContent strings.Builder

	// Current stage with spinner
	if m.stage != "" && !m.passwordMode && !m.lockedOut {
		mainContent.WriteString(fmt.Sprintf("%s %s %s\n", clearLine, m.spinner.View(), stageStyle.Render(m.stage)))
	}

	// TPM Lockout display (no password prompt)
	if m.lockedOut {
		mainContent.WriteString("\n")
		mainContent.WriteString(errorStyle.Render("⚠ TPM Locked"))
		mainContent.WriteString("\n\n")
		mainContent.WriteString(stageStyle.Render(m.lockoutMessage))
		mainContent.WriteString("\n")
		if m.lockoutRecovery != "" {
			mainContent.WriteString("\n")
			mainContent.WriteString(helpStyle.Render(m.lockoutRecovery))
			mainContent.WriteString("\n")
		}
	}

	// Password prompt
	if m.passwordMode {
		if m.stage != "" {
			mainContent.WriteString(fmt.Sprintf("%s %s %s\n", clearLine, m.spinner.View(), stageStyle.Render(m.stage)))
		}
		mainContent.WriteString("\n")
		// Show error from previous attempt BEFORE the new prompt
		if m.passwordErr != "" {
			mainContent.WriteString(errorStyle.Render(m.passwordErr))
			mainContent.WriteString("\n\n")
		}
		// Show attempt counter (1-indexed, always show current attempt)
		attemptNum := m.attempts + 1
		if attemptNum <= maxPromptAttempts {
			mainContent.WriteString(helpStyle.Render(fmt.Sprintf("Attempt %d of %d", attemptNum, maxPromptAttempts)))
			mainContent.WriteString("\n\n")
		}
		mainContent.WriteString(promptStyle.Render(fmt.Sprintf("Enter passphrase for %s:", m.deviceName)))
		mainContent.WriteString("\n\n")
		mainContent.WriteString(m.passwordInput.View())
		mainContent.WriteString("\n")
	}

	// Standalone TPM error (outside password mode)
	if m.tpmError != "" {
		mainContent.WriteString("\n")
		mainContent.WriteString(errorStyle.Render(m.tpmError))
		mainContent.WriteString("\n")
	}

	if m.err != nil {
		mainContent.WriteString("\n" + errorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n")
	}

	// Assemble the centralized block
	// We use JoinVertical to stack Logo, Title, and MainContent
	ui := lipgloss.JoinVertical(lipgloss.Center,
		Logo,
		"\n",
		title,
		"\n\n",
		mainContent.String(),
	)

	// Center the UI block in the entire window
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, ui)
}

// Program is the global TUI program instance
var Program *tea.Program

// running reports whether the TUI's Run loop is actually alive. Program
// stays non-nil while the start goroutine is still inside Run() (and even
// after it returned — until Quit() runs), so liveness checks must look at
// this flag rather than a nil-check on Program alone.
var running atomic.Bool

// runExited is closed when Run() returns for any reason (start failure,
// user pressed q/ctrl+c in stage mode, fatal model error). Prompt callers
// select on it to fail fast instead of blocking until their timeout when
// the TUI is already dead.
var runExited chan struct{}

// suppressKernelMessages aggressively suppresses kernel console output
func suppressKernelMessages() {
	// Set console log level to 0 (suppress all messages)
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("0 0 0 0"), 0644)
	// Also disable kernel console output via sysctl
	_ = os.WriteFile("/proc/sys/kernel/printk_devkmsg", []byte("off"), 0644)
}

// restoreKernelMessages restores kernel console output
func restoreKernelMessages() {
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("4 4 1 7"), 0644)
	_ = os.WriteFile("/proc/sys/kernel/printk_devkmsg", []byte("on"), 0644)
}

// Start initializes and starts the TUI
func Start() error {
	// Suppress kernel messages before starting TUI
	suppressKernelMessages()

	// Suppress console output to avoid interfering with TUI
	console.SetTUIActive(true)

	m := New()
	Program = tea.NewProgram(m, tea.WithAltScreen())
	runExited = make(chan struct{})
	running.Store(true)

	go func() {
		// Mark the TUI dead when Run returns, whatever the reason: a
		// failed start, an error inside the model, or the user quitting
		// outside password mode. Without this, console output stays
		// suppressed and prompt calls block until their timeout with
		// nothing visible on screen.
		defer func() {
			running.Store(false)
			console.SetTUIActive(false)
			close(runExited)
			restoreKernelMessages()
		}()
		if _, err := Program.Run(); err != nil {
			// The TUI failed; prompt callers fall back to the console
			// via PromptAvailable.
		}
	}()

	// Give the TUI time to initialize before returning
	time.Sleep(100 * time.Millisecond)

	return nil
}

// UpdateStage sends a stage update to the TUI
func UpdateStage(stage string) {
	if Program != nil {
		Program.Send(StageMsg(stage))
	}
}

// StageDone marks a stage as completed
func StageDone(stage string) {
	if Program != nil {
		Program.Send(StageDoneMsg(stage))
	}
}

// StageError marks a stage as failed
func StageError(stage string, err error) {
	if Program != nil {
		Program.Send(StageErrorMsg{Stage: stage, Err: err})
	}
}

// ErrPromptUnavailable is returned by the prompt entry points when the TUI
// cannot accept a prompt (no program, Run loop dead, or debug builds).
// Callers treat it as "fall back to the plain console".
var ErrPromptUnavailable = fmt.Errorf("TUI not available")

// PromptAvailable reports whether the TUI can currently accept password
// prompts. IsEnabled() is a build-tag constant and says nothing about the
// runtime state; this checks that the Run loop is actually alive. Callers
// route prompts through it so a dead TUI (quit before the prompt, start
// failure, user exited) falls back to the plain console instead of
// blocking on the prompt timeout.
func PromptAvailable() bool {
	return Program != nil && running.Load()
}

// PromptPassword prompts for a password via the TUI
// Returns the entered password or an error
func PromptPassword(device string) (string, error) {
	if !PromptAvailable() {
		return "", ErrPromptUnavailable
	}

	done := make(chan string, 1)
	Program.Send(PasswordPromptMsg{Device: device, Done: done})

	select {
	case password := <-done:
		return password, nil
	case <-runExited:
		// A result may already be queued (e.g. the user pressed ctrl+c and
		// the Run loop exited). Prefer it over the exit signal: otherwise a
		// cancel would randomly turn into "TUI unavailable" and the caller
		// would re-prompt on the console.
		select {
		case password := <-done:
			return password, nil
		default:
		}
		return "", fmt.Errorf("%w: TUI exited before password entry", ErrPromptUnavailable)
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("password prompt timeout")
	}
}

// PasswordError shows a password error message
func PasswordError(msg string) {
	if Program != nil {
		Program.Send(PasswordErrorMsg(msg))
	}
}

// PasswordErrorWithRetry shows a password error and waits for retry
// Returns the next password attempt
func PasswordErrorWithRetry(msg string) (string, error) {
	if !PromptAvailable() {
		return "", ErrPromptUnavailable
	}

	done := make(chan string, 1)
	Program.Send(PasswordErrorWithRetryMsg{Message: msg, Done: done})

	select {
	case password := <-done:
		return password, nil
	case <-runExited:
		// A result may already be queued (e.g. the user pressed ctrl+c and
		// the Run loop exited). Prefer it over the exit signal: otherwise a
		// cancel would randomly turn into "TUI unavailable" and the caller
		// would re-prompt on the console.
		select {
		case password := <-done:
			return password, nil
		default:
		}
		return "", fmt.Errorf("%w: TUI exited before password entry", ErrPromptUnavailable)
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("password prompt timeout")
	}
}

// PasswordPromptDone signals that password entry is complete
// Call this after successful unlock or when giving up on PIN entry
func PasswordPromptDone() {
	if Program != nil {
		Program.Send(PasswordPromptDoneMsg{})
	}
}

// ShowTPMLockout displays a lockout message without PIN prompt
// Use when TPM is in DA lockout state before prompting for PIN
func ShowTPMLockout(message, recoveryHint string) {
	if Program != nil {
		Program.Send(TPMLockoutMsg{Message: message, RecoveryHint: recoveryHint})
	}
}

// ShowTPMError displays a TPM error that prevents unlock
// Use for non-retryable errors like PCR mismatch
func ShowTPMError(message string) {
	if Program != nil {
		Program.Send(TPMErrorMsg{Message: message})
	}
}

// Quit stops the TUI and waits for it to fully terminate
func Quit() {
	if Program != nil {
		// Send quit message
		Program.Send(QuitMsg{})

		// Wait for program to exit with timeout
		// This ensures alternate screen is restored and TTY is released
		done := make(chan struct{})
		go func() {
			Program.Wait()
			close(done)
		}()
		select {
		case <-done:
			// Program exited cleanly
		case <-time.After(2 * time.Second):
			// Timeout - force continue to avoid blocking boot
		}

		Program = nil
		running.Store(false)
		console.SetTUIActive(false)
		restoreKernelMessages()
	}
}

// ForceReset sends terminal reset sequences to restore TTY state.
// Call this after Quit() to ensure clean handover to new init.
// This handles edge cases where the TUI cleanup didn't fully restore the terminal.
func ForceReset() {
	// Reset terminal to sane state
	// - Exit alternate screen buffer (if still in it)
	// - Show cursor
	// - Reset attributes
	// - Clear screen
	fmt.Print("\033[?1049l") // Exit alternate screen
	fmt.Print("\033[?25h")   // Show cursor
	fmt.Print("\033[0m")     // Reset attributes
	fmt.Print("\033[2J")     // Clear entire screen
	fmt.Print("\033[H")      // Move cursor to home position
}

// IsEnabled returns true when TUI is available
func IsEnabled() bool {
	return true
}
