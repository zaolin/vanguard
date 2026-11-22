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

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

const (
	// socketWaitTimeout is how long to wait for the swtpm unix socket to
	// appear after spawning the process. Under a parallel `go test ./...`
	// the machine starts several swtpm instances at once; 5s proved to be
	// too short there and produced spurious failures while the same tests
	// passed in isolation.
	socketWaitTimeout = 30 * time.Second

	// readyProbeTimeout is how long to wait for swtpm to actually answer
	// TPM commands after the socket exists. The socket file can be visible
	// before swtpm has finished initializing the emulated TPM state
	// machine, particularly under CI load — sending commands during that
	// window either fails intermittently or hangs. We therefore issue a
	// trivial GetCapability until it succeeds.
	readyProbeTimeout = 30 * time.Second

	// probeInterval is how often to retry the readiness probe.
	probeInterval = 50 * time.Millisecond
)

// startSwtpm spawns a swtpm instance and waits until it answers TPM
// commands. Returns an open transport + cleanup function, or an error.
//
// The temp dir is created by the caller (t.TempDir() for Setup so Go
// auto-cleans, os.MkdirTemp for TrySetup which manages it manually via
// the returned cleanup).
func startSwtpm(tmpDir string) (transport.TPMCloser, func(), error) {
	socketPath := filepath.Join(tmpDir, "swtpm.sock")
	ctrlPath := filepath.Join(tmpDir, "swtpm.sock.ctrl")
	tpmStateDir := filepath.Join(tmpDir, "tpm-state")
	if err := os.MkdirAll(tpmStateDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("mkdir tpm-state: %w", err)
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
		return nil, nil, fmt.Errorf("start swtpm: %w", err)
	}

	// killNow tears down the process when a later step fails — used on
	// error paths before the caller gets a cleanup function.
	killNow := func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}

	// Wait for the socket to appear
	socketDeadline := time.Now().Add(socketWaitTimeout)
	for time.Now().Before(socketDeadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(probeInterval)
	}
	if _, err := os.Stat(socketPath); err != nil {
		killNow()
		// Include swtpm's own log: "the socket did not appear" alone does
		// not say whether the binary is missing a backend, crashed, or was
		// simply too slow under parallel test load.
		logData, _ := os.ReadFile(filepath.Join(tmpDir, "swtpm.log"))
		return nil, nil, fmt.Errorf("swtpm socket did not appear within %v: %w\nswtpm log:\n%s", socketWaitTimeout, err, logData)
	}

	// Probe readiness: the socket can exist before swtpm is ready to
	// serve TPM commands. Retry Open + GetCapability until one succeeds.
	readyDeadline := time.Now().Add(readyProbeTimeout)
	var lastErr error
	for time.Now().Before(readyDeadline) {
		tpm, err := linuxudstpm.Open(socketPath)
		if err != nil {
			lastErr = fmt.Errorf("open transport: %w", err)
			time.Sleep(probeInterval)
			continue
		}
		// Socket connected — verify the TPM accepts commands.
		probe := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(tpm2.TPMPTFamilyIndicator),
			PropertyCount: 1,
		}
		if _, err := probe.Execute(tpm); err != nil {
			lastErr = fmt.Errorf("readiness probe: %w", err)
			tpm.Close()
			time.Sleep(probeInterval)
			continue
		}

		cleanup := func() {
			tpm.Close()
			if cmd.Process != nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		}
		return tpm, cleanup, nil
	}

	killNow()
	return nil, nil, fmt.Errorf("swtpm not ready after %v: %w", readyProbeTimeout, lastErr)
}

// Setup starts a swtpm instance and returns a transport connected to it,
// along with a cleanup function that stops swtpm and removes the temp dir.
//
// A missing simulator is an environment limitation and skips the test. An
// installed simulator that cannot be started is a harness problem and fails
// loudly — otherwise a broken harness would silently skip the TPM suite.
func Setup(t *testing.T) (transport.TPMCloser, func()) {
	t.Helper()

	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed - skipping TPM integration test")
	}
	tpm, cleanup, _ := startSwtpmRetry(t)
	return tpm, cleanup
}

// SetupEnvTransport starts an swtpm instance, points VANGUARD_TPM_SOCKET at it
// and returns a transport connected to that same simulator.
//
// Use this for code under test that opens its TPM itself via tpm.New(); the
// returned transport lets the test talk to the same simulator (e.g. to create
// NV indexes). Callers that only need the environment may discard it — the
// transport is closed by the registered cleanup.
//
// A missing simulator is an environment limitation and skips the test; an
// installed one that cannot start fails loudly.
func SetupEnvTransport(t *testing.T) transport.TPMCloser {
	t.Helper()

	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed - skipping TPM integration test")
	}

	tpm, cleanup, socketPath := startSwtpmRetry(t)
	t.Cleanup(cleanup)
	t.Setenv("VANGUARD_TPM_SOCKET", socketPath)
	return tpm
}

// startSwtpmRetry starts an swtpm instance in a fresh temp dir, retrying a
// failed start once.
//
// Under a parallel `go test ./...` several test binaries start swtpm at the
// same time and a start can be lost to that contention. A single retry
// absorbs it; a genuinely broken simulator fails both attempts and is
// reported loudly, so the harness cannot silently skip the TPM suite.
func startSwtpmRetry(t *testing.T) (transport.TPMCloser, func(), string) {
	t.Helper()

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		tmpDir := t.TempDir()
		tpm, cleanup, err := startSwtpm(tmpDir)
		if err == nil {
			return tpm, cleanup, filepath.Join(tmpDir, "swtpm.sock")
		}
		lastErr = err
		t.Logf("swtpm start attempt %d failed: %v", attempt, err)
	}
	t.Fatalf("swtpm could not be started: %v", lastErr)
	return nil, nil, ""
}

// TrySetup is like Setup but returns an error instead of calling t.Fatal /
// t.Skip. Use it when the caller wants to decide how to handle swtpm
// being unavailable.
func TrySetup() (transport.TPMCloser, func(), error) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return nil, nil, fmt.Errorf("swtpm not found: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "swtpm-test-")
	if err != nil {
		return nil, nil, fmt.Errorf("mkdir temp: %w", err)
	}

	tpm, cleanup, err := startSwtpm(tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, err
	}

	// Wrap cleanup so the temp dir is always removed. startSwtpm's
	// cleanup closes the transport and kills the process.
	orig := cleanup
	wrapped := func() {
		orig()
		os.RemoveAll(tmpDir)
	}
	return tpm, wrapped, nil
}
