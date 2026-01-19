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

// DlopenLibraries contains libraries loaded via dlopen that won't show in ldd
// These must be explicitly included
var DlopenLibraries = []string{
	"/usr/lib64/cryptsetup/libcryptsetup-token-systemd-tpm2.so",
	// libgcc_s is dlopened by glibc for pthread_exit/pthread_cancel
	"/usr/lib/gcc/x86_64-pc-linux-gnu/15/libgcc_s.so.1",
	"/usr/lib/gcc/x86_64-pc-linux-gnu/14/libgcc_s.so.1",
	"/lib64/libgcc_s.so.1",
	"/usr/lib64/libgcc_s.so.1",
	// TPM2 libraries dlopened by systemd/plugin
	"/usr/lib64/libtss2-tctildr.so.0",
	"/usr/lib64/libtss2-tcti-device.so.0",
	"/usr/lib64/libtss2-mu.so.0",
	"/usr/lib64/libtss2-esys.so.0",
	"/usr/lib64/libtss2-rc.so.0",
	// libcryptsetup-token-systemd-tpm2 depends on this non-standard path lib
	"/usr/lib64/systemd/libsystemd-shared-259.so",
	// udevd may dlopen these for device management
	"/usr/lib64/libudev.so.1",
	"/usr/lib64/libkmod.so.2",
	"/lib64/libudev.so.1",
	"/lib64/libkmod.so.2",
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
			libPath := findLibrary(lib)
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

// findLibrary searches for a library in standard paths
func findLibrary(name string) string {
	// Handle absolute paths
	if strings.HasPrefix(name, "/") {
		if _, err := os.Stat(name); err == nil {
			return name
		}
		return ""
	}

	// Search in standard library paths
	for _, dir := range libraryPaths {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// ResolveDlopenDependencies resolves dependencies of libraries loaded via dlopen
func ResolveDlopenDependencies() ([]LibraryFile, error) {
	var result []LibraryFile
	seen := make(map[string]bool)

	for _, lib := range DlopenLibraries {
		if _, err := os.Stat(lib); err != nil {
			// Skip if library doesn't exist
			continue
		}

		if !seen[lib] {
			seen[lib] = true

			// Determine destination path
			dstPath := lib
			basename := filepath.Base(lib)
			// Special case: libgcc_s needs to be in /lib64 for runtime linker
			if strings.Contains(basename, "libgcc_s") {
				dstPath = "/lib64/" + basename
			}
			// Special case: libsystemd-shared is in /usr/lib64/systemd on host, but we want it in /usr/lib64
			if strings.Contains(basename, "libsystemd-shared") {
				dstPath = "/usr/lib64/" + basename
			}

			result = append(result, LibraryFile{
				SrcPath: lib,
				DstPath: dstPath,
			})

			// Resolve dependencies of the dlopen library
			deps, err := ResolveDependencies(lib)
			if err != nil {
				continue
			}
			for _, dep := range deps {
				if !seen[dep.SrcPath] {
					seen[dep.SrcPath] = true
					result = append(result, dep)
				}
			}
		}
	}

	return result, nil
}
