package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPolicyPathForUKI pins the derivation of the policy path from the UKI
// path. The stripping is case-insensitive, so the policy lookup (status),
// the policy generation (update) and the enrollment (enroll) always agree
// on the file name — otherwise a UKI named kernel.EFI would make status
// look for "kernel.EFI.pcrlock.json" while update wrote "kernel.pcrlock.json".
func TestPolicyPathForUKI(t *testing.T) {
	cases := []struct {
		uki  string
		want string
	}{
		{"/boot/EFI/Gentoo/kernel.efi", "/boot/EFI/Gentoo/kernel.pcrlock.json"},
		{"/boot/EFI/Gentoo/kernel.EFI", "/boot/EFI/Gentoo/kernel.pcrlock.json"},
		{"/boot/EFI/Gentoo/kernel.Efi", "/boot/EFI/Gentoo/kernel.pcrlock.json"},
		{"/boot/EFI/Boot/BOOTX64.EFI", "/boot/EFI/Boot/BOOTX64.pcrlock.json"},
		{"/boot/EFI/Gentoo/kernel", "/boot/EFI/Gentoo/kernel.pcrlock.json"},
	}
	for _, tc := range cases {
		if got := policyPathForUKI(tc.uki); got != tc.want {
			t.Errorf("policyPathForUKI(%q) = %q, want %q", tc.uki, got, tc.want)
		}
	}
}

// policyTestEnv isolates the policy lookup from the host: every source the
// selection consults is pointed at a temporary directory.
type policyTestEnv struct {
	dir string
}

func setupPolicyTestEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	dir := t.TempDir()

	origBooted := bootedUKIPathFn
	origMatching := policyMatchingTokenNVFn
	origStandard := standardPolicyPaths
	origInstalled := installedPolicies
	t.Cleanup(func() {
		bootedUKIPathFn = origBooted
		policyMatchingTokenNVFn = origMatching
		standardPolicyPaths = origStandard
		installedPolicies = origInstalled
	})

	env := &policyTestEnv{dir: dir}
	// By default nothing is found anywhere.
	bootedUKIPathFn = func() string { return "" }
	policyMatchingTokenNVFn = func() string { return "" }
	standardPolicyPaths = func() []string { return nil }
	installedPolicies = func() []string { return nil }
	return env
}

// write creates a file below the test directory and returns its path.
func (e *policyTestEnv) write(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(e.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFindPCRLockPolicyPrefersBootedUKI pins the documented precedence: the
// policy of the booted UKI wins over every other source. Picking another
// policy would report the NV index of a policy that is not in use.
func TestFindPCRLockPolicyPrefersBootedUKI(t *testing.T) {
	env := setupPolicyTestEnv(t)

	booted := env.write(t, "booted.pcrlock.json")
	other := env.write(t, "other.pcrlock.json")

	bootedUKIPathFn = func() string { return filepath.Join(env.dir, "kernel.EFI") }
	// The booted UKI's policy must be at the derived path.
	derived := policyPathForUKI(filepath.Join(env.dir, "kernel.EFI"))
	if err := os.Rename(booted, derived); err != nil {
		t.Fatal(err)
	}
	booted = derived

	policyMatchingTokenNVFn = func() string { return other }
	standardPolicyPaths = func() []string { return []string{other} }
	installedPolicies = func() []string { return []string{other} }

	if got := findPCRLockPolicy(); got != booted {
		t.Errorf("findPCRLockPolicy = %q, want the booted UKI's policy %q", got, booted)
	}
}

// TestFindPCRLockPolicySkipsMissingBootedPolicy pins that a booted UKI whose
// policy file does not exist falls through to the token match.
func TestFindPCRLockPolicySkipsMissingBootedPolicy(t *testing.T) {
	env := setupPolicyTestEnv(t)

	tokenPolicy := env.write(t, "token.pcrlock.json")
	bootedUKIPathFn = func() string { return filepath.Join(env.dir, "missing.efi") }
	policyMatchingTokenNVFn = func() string { return tokenPolicy }

	if got := findPCRLockPolicy(); got != tokenPolicy {
		t.Errorf("findPCRLockPolicy = %q, want %q", got, tokenPolicy)
	}
}

// TestFindPCRLockPolicySkipsMissingTokenPolicy pins that a token match
// pointing at a removed file is not reported as the active policy.
func TestFindPCRLockPolicySkipsMissingTokenPolicy(t *testing.T) {
	env := setupPolicyTestEnv(t)

	standard := env.write(t, "standard.pcrlock.json")
	policyMatchingTokenNVFn = func() string { return filepath.Join(env.dir, "gone.pcrlock.json") }
	standardPolicyPaths = func() []string { return []string{standard} }

	if got := findPCRLockPolicy(); got != standard {
		t.Errorf("findPCRLockPolicy = %q, want %q", got, standard)
	}
}

// TestFindPCRLockPolicyFallsBackToInstalledPolicies pins the last resort:
// a policy installed below the ESP.
func TestFindPCRLockPolicyFallsBackToInstalledPolicies(t *testing.T) {
	env := setupPolicyTestEnv(t)

	installed := env.write(t, "installed.pcrlock.json")
	installedPolicies = func() []string { return []string{installed} }

	if got := findPCRLockPolicy(); got != installed {
		t.Errorf("findPCRLockPolicy = %q, want %q", got, installed)
	}
}

// TestFindPCRLockPolicyNone pins that no policy at all yields an empty
// result rather than an invented path.
func TestFindPCRLockPolicyNone(t *testing.T) {
	setupPolicyTestEnv(t)
	if got := findPCRLockPolicy(); got != "" {
		t.Errorf("findPCRLockPolicy = %q, want empty", got)
	}
}

// TestFindPCRLockPolicyAmbiguousInstalledPolicies pins that several installed
// candidates are NOT resolved by picking the first: the active policy would be
// a guess and could produce a false NV-tampering diagnosis.
func TestFindPCRLockPolicyAmbiguousInstalledPolicies(t *testing.T) {
	env := setupPolicyTestEnv(t)

	first := env.write(t, "a.pcrlock.json")
	second := env.write(t, "b.pcrlock.json")
	installedPolicies = func() []string { return []string{first, second} }

	if got := findPCRLockPolicy(); got != "" {
		t.Errorf("findPCRLockPolicy = %q with two candidates, want empty (ambiguous)", got)
	}
}

// TestESPMountPointFallback documents that the ESP mount point defaults to
// /boot when fstab carries no ESP entry.
func TestESPMountPointFallback(t *testing.T) {
	// The function reads /etc/fstab; on a machine without one it must
	// fall back to /boot rather than returning an empty path.
	mp := espMountPoint()
	if mp == "" {
		t.Error("espMountPoint returned an empty mount point")
	}
	if !filepath.IsAbs(mp) {
		t.Errorf("espMountPoint = %q, want an absolute path", mp)
	}
}
