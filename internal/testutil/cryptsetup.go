// Package testutil provides shared helpers for the vanguard test suites.
//
// It must never be imported by production code — it exists only for
// tests.
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	cryptsetupOnce sync.Once
	cryptsetupOK   bool
	cryptsetupWhy  string
)

// CryptsetupUsable reports whether cryptsetup is installed AND able to
// format a LUKS2 container in this environment.
//
// Checking only for the binary on PATH is not enough: on systems without
// the kernel crypto modules (af_alg / crypto_user, e.g. minimal containers
// or sandboxes), cryptsetup is present but fails every operation with
// "Failed to initialize the crypto backend". Tests that need a real LUKS2
// container must skip in that case instead of reporting a failure that
// says nothing about the code under test.
//
// The probe result is cached: the check runs at most once per test binary.
func CryptsetupUsable() (bool, string) {
	cryptsetupOnce.Do(func() {
		path, err := exec.LookPath("cryptsetup")
		if err != nil {
			cryptsetupWhy = "cryptsetup not found on PATH"
			return
		}

		dir, err := os.MkdirTemp("", "vanguard-cryptsetup-probe-")
		if err != nil {
			cryptsetupWhy = "cannot create probe directory: " + err.Error()
			return
		}
		defer os.RemoveAll(dir)

		probe := filepath.Join(dir, "probe.img")
		f, err := os.Create(probe)
		if err != nil {
			cryptsetupWhy = "cannot create probe file: " + err.Error()
			return
		}
		if err := f.Truncate(16 * 1024 * 1024); err != nil {
			f.Close()
			cryptsetupWhy = "cannot size probe file: " + err.Error()
			return
		}
		f.Close()
		defer os.Remove(probe)

		// Minimal-cost format: few PBKDF iterations, no keyfile.
		cmd := exec.Command(path, "luksFormat", "--type", "luks2", "-q",
			"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", probe)
		cmd.Stdin = strings.NewReader("probe-passphrase\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			cryptsetupWhy = "cryptsetup cannot format a LUKS2 container here: " +
				strings.TrimSpace(string(out))
			return
		}
		cryptsetupOK = true
	})
	return cryptsetupOK, cryptsetupWhy
}

// RequireCryptsetup skips the test when cryptsetup is missing or not
// usable in this environment.
func RequireCryptsetup(t *testing.T) {
	t.Helper()
	ok, why := CryptsetupUsable()
	if !ok {
		t.Skip("skipping: " + why)
	}
}
