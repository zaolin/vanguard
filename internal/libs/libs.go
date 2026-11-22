package libs

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
)

// Library search paths (standard Linux library directories)
var libraryPaths = []string{
	"/lib64",
	"/lib",
	"/usr/lib64",
	"/usr/lib",
	"/usr/local/lib64",
	"/usr/local/lib",
}

// LibraryFile represents a library to include in the initramfs
type LibraryFile struct {
	SrcPath string // Absolute path on host
	DstPath string // Path in initramfs
}

// ResolveDependencies finds all shared library dependencies for a binary
func ResolveDependencies(binaryPath string) ([]LibraryFile, error) {
	seen := make(map[string]bool)
	var result []LibraryFile

	// Search paths for the transitive dependencies. The binary's own
	// RPATH/RUNPATH comes first — systemd's udevd, for example, needs
	// libsystemd-shared-*.so which lives in /usr/lib64/systemd and is
	// ONLY reachable through the binary's RUNPATH. Without this, the
	// library was silently omitted from the initramfs and udevd failed
	// to start at boot.
	searchPaths := libraryPaths
	if rpaths := runPathsOf(binaryPath); len(rpaths) > 0 {
		searchPaths = append(append([]string{}, rpaths...), libraryPaths...)
	}

	var resolve func(path string) error
	resolve = func(path string) error {
		if seen[path] {
			return nil
		}
		seen[path] = true

		f, err := elf.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		libs, err := f.ImportedLibraries()
		if err != nil {
			return err
		}

		for _, lib := range libs {
			libPath := findLibraryIn(lib, searchPaths)
			if libPath != "" && !seen[libPath] {
				// Preserve the original directory structure
				// e.g., /lib64/foo.so -> /lib64/foo.so, /usr/lib/bar.so -> /usr/lib/bar.so
				result = append(result, LibraryFile{
					SrcPath: libPath,
					DstPath: libPath, // Keep original path
				})
				if err := resolve(libPath); err != nil {
					// Log but don't fail on nested resolution
					continue
				}
			}
		}
		return nil
	}

	if err := resolve(binaryPath); err != nil {
		return nil, err
	}

	return result, nil
}

// runPathsOf returns the RPATH/RUNPATH entries of an ELF binary. Used to
// locate libraries that are not in the standard library directories (e.g.
// systemd's libsystemd-shared-*.so in /usr/lib64/systemd).
func runPathsOf(binaryPath string) []string {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// DT_RUNPATH (2) and DT_RPATH (15)
	var paths []string
	if entries, err := f.DynString(elf.DT_RUNPATH); err == nil {
		paths = append(paths, entries...)
	}
	if entries, err := f.DynString(elf.DT_RPATH); err == nil {
		paths = append(paths, entries...)
	}
	return paths
}

// findLibrary searches for a library in the standard paths
func findLibrary(name string) string {
	return findLibraryIn(name, libraryPaths)
}

// findLibraryIn searches for a library in the given directories. Callers
// pass the standard library paths, optionally prefixed with the binary's
// RUNPATH.
func findLibraryIn(name string, searchPaths []string) string {
	// Handle absolute paths
	if strings.HasPrefix(name, "/") {
		if _, err := os.Stat(name); err == nil {
			return name
		}
		return ""
	}

	// Search in the given paths (may include the binary's RUNPATH)
	for _, dir := range searchPaths {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}
