package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zaolin/vanguard/init/console"
	"golang.org/x/sys/unix"
)

// Module represents a kernel module to load
type Module struct {
	Name string
	Path string // Path to .ko file
}

// Load loads a kernel module using finit_module syscall
func Load(modulePath string, params string) error {
	f, err := os.Open(modulePath)
	if err != nil {
		return fmt.Errorf("open module %s: %w", modulePath, err)
	}
	defer f.Close()

	// Use finit_module syscall (more secure than init_module)
	err = unix.FinitModule(int(f.Fd()), params, 0)
	if err != nil {
		// Check if already loaded
		if err == unix.EEXIST {
			return nil
		}
		return fmt.Errorf("finit_module %s: %w", modulePath, err)
	}

	return nil
}

// LoadByName loads a module by name, searching in standard paths
func LoadByName(name string) error {
	// Get kernel version
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	release := unix.ByteSliceToString(uname.Release[:])

	// Search paths for modules
	searchPaths := []string{
		filepath.Join("/lib/modules", release),
		"/lib/modules",
	}

	// Normalize module name (replace - with _)
	normalizedName := strings.ReplaceAll(name, "-", "_")

	for _, basePath := range searchPaths {
		modulePath, err := findModule(basePath, normalizedName)
		if err == nil && modulePath != "" {
			return Load(modulePath, "")
		}
	}

	return fmt.Errorf("module %s not found", name)
}

// findModule searches for a module file in the given base path
func findModule(basePath, name string) (string, error) {
	var foundPath string

	err := filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if d.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		// Check for .ko, .ko.gz, .ko.xz, .ko.zst
		if strings.HasPrefix(base, name+".ko") {
			foundPath = path
			return filepath.SkipAll
		}

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return "", err
	}

	return foundPath, nil
}

// LoadDependencies loads a module and its dependencies from modules.dep
func LoadDependencies(name string) error {
	// Get kernel version
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	release := unix.ByteSliceToString(uname.Release[:])

	depPath := filepath.Join("/lib/modules", release, "modules.dep")
	deps, err := parseDependencies(depPath, name)
	if err != nil {
		// If no deps file, just try to load the module directly
		return LoadByName(name)
	}

	// Load dependencies first (in order)
	for _, dep := range deps {
		if err := LoadByName(dep); err != nil {
			// Log but continue
			console.DebugPrint("modules: warning: failed to load dependency %s: %v\n", dep, err)
		}
	}

	// Load the requested module
	return LoadByName(name)
}

// parseDependencies parses modules.dep to find dependencies for a module
func parseDependencies(depPath, name string) ([]string, error) {
	f, err := os.Open(depPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	normalizedName := strings.ReplaceAll(name, "-", "_")

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		// Check if this is our module
		modPath := parts[0]
		modBase := filepath.Base(modPath)
		modName := strings.TrimSuffix(modBase, filepath.Ext(modBase))
		// Handle .ko.gz, .ko.xz etc
		for strings.Contains(modName, ".") {
			modName = strings.TrimSuffix(modName, filepath.Ext(modName))
		}
		modName = strings.ReplaceAll(modName, "-", "_")

		if modName == normalizedName {
			// Parse dependencies
			depStr := strings.TrimSpace(parts[1])
			if depStr == "" {
				return nil, nil // No dependencies
			}

			var deps []string
			for _, dep := range strings.Fields(depStr) {
				depBase := filepath.Base(dep)
				depName := strings.TrimSuffix(depBase, filepath.Ext(depBase))
				for strings.Contains(depName, ".") {
					depName = strings.TrimSuffix(depName, filepath.Ext(depName))
				}
				deps = append(deps, depName)
			}

			// Reverse order (dependencies should be loaded first)
			for i, j := 0, len(deps)-1; i < j; i, j = i+1, j-1 {
				deps[i], deps[j] = deps[j], deps[i]
			}

			return deps, nil
		}
	}

	return nil, fmt.Errorf("module %s not found in modules.dep", name)
}

// IsLoaded checks if a module is already loaded
func IsLoaded(name string) bool {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return false
	}
	defer f.Close()

	normalizedName := strings.ReplaceAll(name, "-", "_")

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			modName := strings.ReplaceAll(fields[0], "-", "_")
			if modName == normalizedName {
				return true
			}
		}
	}

	return false
}

// LoadAll loads multiple modules, handling dependencies
func LoadAll(modules []string) error {
	for _, mod := range modules {
		if IsLoaded(mod) {
			continue
		}
		if err := LoadDependencies(mod); err != nil {
			// Log but continue with other modules
			console.DebugPrint("modules: warning: failed to load %s: %v\n", mod, err)
		}
	}
	return nil
}
