package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KernelModulesDir is the base directory for kernel modules in the initramfs
const KernelModulesDir = "/lib/modules"

// ModuleFile represents a kernel module file
type ModuleFile struct {
	Name    string // Module name (e.g., "nvme")
	SrcPath string // Source path on host
	DstPath string // Destination path in initramfs
}

// Collect gathers kernel module files for the given module names
func Collect(moduleNames []string, kernelVer string) ([]ModuleFile, error) {
	if kernelVer == "" {
		// Default to current kernel
		data, err := os.ReadFile("/proc/version")
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			kernelVer = fields[2]
		}
	}

	basePath := filepath.Join("/lib/modules", kernelVer)

	var modules []ModuleFile
	seen := make(map[string]bool)

	// Load modules.dep for dependency resolution
	depPath := filepath.Join(basePath, "modules.dep")
	deps, err := loadModulesDep(depPath)
	if err != nil {
		fmt.Printf("modules: warning: failed to load modules.dep: %v\n", err)
		deps = make(map[string][]string)
	}

	// Collect each module and its dependencies
	for _, name := range moduleNames {
		collectWithDeps(name, basePath, deps, seen, &modules)
	}

	return modules, nil
}

// collectWithDeps collects a module and its dependencies
func collectWithDeps(name, basePath string, deps map[string][]string, seen map[string]bool, modules *[]ModuleFile) {
	normalizedName := strings.ReplaceAll(name, "-", "_")
	if seen[normalizedName] {
		return
	}
	seen[normalizedName] = true

	// Collect dependencies first
	if modDeps, ok := deps[normalizedName]; ok {
		for _, dep := range modDeps {
			collectWithDeps(dep, basePath, deps, seen, modules)
		}
	}

	// Find the module file
	modPath, err := findModuleFile(basePath, normalizedName)
	if err != nil || modPath == "" {
		fmt.Printf("modules: warning: module %s not found\n", name)
		return
	}

	relPath, _ := filepath.Rel(basePath, modPath)
	*modules = append(*modules, ModuleFile{
		Name:    normalizedName,
		SrcPath: modPath,
		DstPath: filepath.Join(KernelModulesDir, filepath.Base(basePath), relPath),
	})
}

// loadModulesDep parses modules.dep file
func loadModulesDep(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	deps := make(map[string][]string)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		modPath := parts[0]
		modName := extractModuleName(modPath)

		depStr := strings.TrimSpace(parts[1])
		if depStr == "" {
			deps[modName] = nil
			continue
		}

		var modDeps []string
		for _, dep := range strings.Fields(depStr) {
			modDeps = append(modDeps, extractModuleName(dep))
		}
		deps[modName] = modDeps
	}

	return deps, scanner.Err()
}

// extractModuleName gets the normalized module name from a path
func extractModuleName(path string) string {
	base := filepath.Base(path)
	// Remove all extensions (.ko, .ko.gz, .ko.xz, .ko.zst)
	name := base
	for ext := filepath.Ext(name); ext != ""; ext = filepath.Ext(name) {
		name = strings.TrimSuffix(name, ext)
	}
	return strings.ReplaceAll(name, "-", "_")
}

// findModuleFile searches for a module file
func findModuleFile(basePath, name string) (string, error) {
	var foundPath string

	err := filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}

		modName := extractModuleName(path)
		if modName == name {
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
