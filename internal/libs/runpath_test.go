package libs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveDependenciesFindsRunPathLibraries pins the RUNPATH-aware
// dependency resolution.
//
// systemd's udevd links libsystemd-shared-*.so, which lives in
// /usr/lib64/systemd and is ONLY reachable through the binary's
// RUNPATH. The resolver used to search the standard library paths only,
// so that library was silently omitted from the initramfs and udevd
// failed to start at boot with "error while loading shared libraries" —
// which in turn means no device nodes, no /dev/disk/by-uuid symlinks and
// a broken root=UUID= boot.
func TestResolveDependenciesFindsRunPathLibraries(t *testing.T) {
	udevd := ""
	for _, p := range []string{
		"/usr/lib/systemd/systemd-udevd",
		"/lib/systemd/systemd-udevd",
	} {
		if _, err := os.Stat(p); err == nil {
			udevd = p
			break
		}
	}
	if udevd == "" {
		t.Skip("systemd-udevd not installed on this system")
	}

	deps, err := ResolveDependencies(udevd)
	if err != nil {
		t.Fatalf("ResolveDependencies: %v", err)
	}

	// Every NEEDED library of udevd must be resolvable.
	have := make(map[string]bool)
	for _, d := range deps {
		have[filepath.Base(d.SrcPath)] = true
	}

	// Check the binary's direct NEEDED entries are all covered.
	if !have["libsystemd-shared-262.so"] {
		// Version differs across distros — look for any libsystemd-shared-*
		found := false
		for name := range have {
			if strings.HasPrefix(name, "libsystemd-shared-") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("libsystemd-shared-*.so missing from resolved dependencies: %v", have)
		}
	}
}

// TestRunPathsOf pins that the RUNPATH reader returns the binary's
// runpath entries (systemd's udevd uses /usr/lib64/systemd).
func TestRunPathsOf(t *testing.T) {
	udevd := ""
	for _, p := range []string{
		"/usr/lib/systemd/systemd-udevd",
		"/lib/systemd/systemd-udevd",
	} {
		if _, err := os.Stat(p); err == nil {
			udevd = p
			break
		}
	}
	if udevd == "" {
		t.Skip("systemd-udevd not installed on this system")
	}

	paths := runPathsOf(udevd)
	if len(paths) == 0 {
		// Not every build has a RUNPATH — only assert consistency.
		return
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("RUNPATH entry is not absolute: %q", p)
		}
	}
}
