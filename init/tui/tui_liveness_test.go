//go:build !debug

package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// TestPromptAvailableTracksLiveness verifies the runtime liveness check
// used to route prompts: available only when a program exists AND its Run
// loop is still going. A stale non-nil Program with a dead Run loop (user
// quit, start failure) must report unavailable so callers fall back to the
// console prompt.
func TestPromptAvailableTracksLiveness(t *testing.T) {
	origProgram, origRunExited := Program, runExited
	t.Cleanup(func() {
		Program = origProgram
		runExited = origRunExited
		running.Store(false)
	})

	// No program at all: never available.
	Program = nil
	running.Store(false)
	if PromptAvailable() {
		t.Error("PromptAvailable() = true with nil Program")
	}

	// Program exists but Run loop is dead (e.g. user pressed q before the
	// prompt, or Run returned an error): unavailable.
	Program = tea.NewProgram(New(), tea.WithAltScreen())
	running.Store(false)
	if PromptAvailable() {
		t.Error("PromptAvailable() = true with dead Run loop")
	}

	// Program exists and Run loop alive: available.
	running.Store(true)
	if !PromptAvailable() {
		t.Error("PromptAvailable() = false with live Run loop")
	}
}

// TestPromptPasswordFailsFastWhenDead verifies PromptPassword does not
// block on the 5-minute timeout when the TUI already exited: it must return
// an error immediately so the caller falls back to the console prompt.
func TestPromptPasswordFailsFastWhenDead(t *testing.T) {
	origProgram, origRunExited := Program, runExited
	t.Cleanup(func() {
		Program = origProgram
		runExited = origRunExited
		running.Store(false)
	})

	Program = nil
	running.Store(false)
	done := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		_, err := PromptPassword("/dev/sda3")
		errc <- err
		done <- ""
	}()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("PromptPassword succeeded with dead TUI, want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PromptPassword blocked with dead TUI")
	}
}
