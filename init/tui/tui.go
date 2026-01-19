//go:build !debug

package tui

import (
	"fmt"
	"os"
	"strings"
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

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86")).
			MarginBottom(1)

	stageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42"))

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
type QuitMsg struct{}

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
	case tea.KeyMsg:
		if m.passwordMode {
			switch msg.Type {
			case tea.KeyEnter:
				password := m.passwordInput.Value()
				m.passwordInput.SetValue("")
				if m.passwordDone != nil {
					m.passwordDone <- password
					m.passwordDone = nil
				}
				m.passwordMode = false
				m.passwordErr = ""
				return m, nil
			case tea.KeyCtrlC:
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
		m.passwordMode = true
		m.deviceName = msg.Device
		m.passwordDone = msg.Done
		m.passwordInput.Focus()
		return m, textinput.Blink

	case PasswordErrorMsg:
		m.passwordErr = string(msg)
		m.attempts++

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
	var b strings.Builder

	// ANSI escape to clear line (prevents artifacts from previous longer text)
	const clearLine = "\033[2K"

	// Title
	b.WriteString(titleStyle.Render("⚡ vanguard boot"))
	b.WriteString("\n\n")

	// Current stage with spinner (always shown unless password mode)
	if m.stage != "" && !m.passwordMode {
		b.WriteString(fmt.Sprintf("%s %s %s\n", clearLine, m.spinner.View(), stageStyle.Render(m.stage)))
	}

	// Password prompt mode - show below the stage
	if m.passwordMode {
		if m.stage != "" {
			b.WriteString(fmt.Sprintf("%s %s %s\n", clearLine, m.spinner.View(), stageStyle.Render(m.stage)))
		}
		b.WriteString("\n")
		b.WriteString(promptStyle.Render(fmt.Sprintf("Enter passphrase for %s:", m.deviceName)))
		b.WriteString("\n\n")
		b.WriteString(m.passwordInput.View())
		b.WriteString("\n\n")
		if m.passwordErr != "" {
			b.WriteString(errorStyle.Render(m.passwordErr))
			b.WriteString("\n")
		}
		if m.attempts > 0 {
			b.WriteString(helpStyle.Render(fmt.Sprintf("Attempt %d of 3", m.attempts+1)))
			b.WriteString("\n")
		}
	}

	if m.err != nil {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render(fmt.Sprintf("Error: %v", m.err)))
		b.WriteString("\n")
	}

	return b.String()
}

// Program is the global TUI program instance
var Program *tea.Program

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
	console.TUIActive = true

	m := New()
	Program = tea.NewProgram(m, tea.WithAltScreen())

	go func() {
		if _, err := Program.Run(); err != nil {
			// TUI failed to start, will fall back to console
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

// PromptPassword prompts for a password via the TUI
// Returns the entered password or an error
func PromptPassword(device string) (string, error) {
	if Program == nil {
		return "", fmt.Errorf("TUI not initialized")
	}

	done := make(chan string, 1)
	Program.Send(PasswordPromptMsg{Device: device, Done: done})

	password := <-done
	return password, nil
}

// PasswordError shows a password error message
func PasswordError(msg string) {
	if Program != nil {
		Program.Send(PasswordErrorMsg(msg))
	}
}

// Quit stops the TUI
func Quit() {
	if Program != nil {
		Program.Send(QuitMsg{})
		// Restore console output and kernel messages after TUI exits
		console.TUIActive = false
		restoreKernelMessages()
	}
}

// IsEnabled returns true when TUI is available
func IsEnabled() bool {
	return true
}
