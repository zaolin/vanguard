//go:build !debug

package buildtags

// DebugEnabled indicates whether debug output is enabled
const DebugEnabled = false

// Debug is a no-op in release builds
func Debug(format string, args ...any) {
	// No output in release mode
}
