// Package swtpmtest provides a test helper that starts a swtpm instance
// and returns a transport connected to it. Tests can use this to test
// TPM operations without real TPM hardware.
//
// Tests skip automatically if swtpm is not installed.
package swtpmtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// Setup starts a swtpm instance and returns a transport connected to it,
// along with a cleanup function that stops swtpm and removes the temp dir.
// Tests are skipped if swtpm is not installed.
func Setup(t *testing.T) (transport.TPMCloser, func()) {
	t.Helper()

	// Check if swtpm is available
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not found - skipping TPM integration test")
	}

	// Create temp directory for swtpm state
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "swtpm.sock")
	ctrlPath := filepath.Join(tmpDir, "swtpm-ctrl.sock")
	tpmStateDir := filepath.Join(tmpDir, "tpm-state")
	if err := os.MkdirAll(tpmStateDir, 0755); err != nil {
		t.Fatalf("mkdir tpm-state: %v", err)
	}

	// Start swtpm with both server (data) and ctrl sockets
	cmd := exec.Command("swtpm", "socket",
		"--tpmstate", "dir="+tpmStateDir,
		"--server", "type=unixio,path="+socketPath,
		"--ctrl", "type=unixio,path="+ctrlPath,
		"--tpm2",
		"--flags", "startup-clear,not-need-init",
		"--log", "level=1,file="+filepath.Join(tmpDir, "swtpm.log"),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start swtpm: %v", err)
	}

	// Wait for the socket to appear
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify socket exists
	if _, err := os.Stat(socketPath); err != nil {
		cmd.Process.Kill()
		t.Fatalf("swtpm socket did not appear: %v", err)
	}

	// Read the swtpm log if there was an issue
	logPath := filepath.Join(tmpDir, "swtpm.log")
	if _, err := os.Stat(logPath); err == nil {
		// Keep for debugging - will be cleaned up by t.TempDir()
	}

	// Open transport via Unix domain socket (data channel)
	tpm, err := linuxudstpm.Open(socketPath)
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("failed to open swtpm transport: %v", err)
	}

	cleanup := func() {
		// Close the transport first
		tpm.Close()

		// Kill swtpm process
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}

	return tpm, cleanup
}

// SetupClient starts a swtpm instance and returns a TPM transport.
// Unlike Setup, it does not auto-skip — the caller decides whether to skip.
// Returns nil transport if swtpm is not available.
func TrySetup() (transport.TPMCloser, func(), error) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return nil, nil, fmt.Errorf("swtpm not found")
	}

	tmpDir, err := os.MkdirTemp("", "swtpm-test-")
	if err != nil {
		return nil, nil, fmt.Errorf("mkdir temp: %w", err)
	}

	socketPath := filepath.Join(tmpDir, "swtpm.sock")
	ctrlPath := filepath.Join(tmpDir, "swtpm-ctrl.sock")
	tpmStateDir := filepath.Join(tmpDir, "tpm-state")
	if err := os.MkdirAll(tpmStateDir, 0755); err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("mkdir tpm-state: %w", err)
	}

	cmd := exec.Command("swtpm", "socket",
		"--tpmstate", "dir="+tpmStateDir,
		"--server", "type=unixio,path="+socketPath,
		"--ctrl", "type=unixio,path="+ctrlPath,
		"--tpm2",
		"--flags", "startup-clear,not-need-init",
		"--log", "level=1,file="+filepath.Join(tmpDir, "swtpm.log"),
	)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("start swtpm: %w", err)
	}

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	tpm, err := linuxudstpm.Open(socketPath)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("open transport: %w", err)
	}

	cleanup := func() {
		tpm.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		os.RemoveAll(tmpDir)
	}

	return tpm, cleanup, nil
}
