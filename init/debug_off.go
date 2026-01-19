//go:build !debug

package main

// debugEnabled indicates whether debug output is enabled
const debugEnabled = false

// debug is a no-op in release builds
func debug(format string, args ...any) {
	// No output in release mode
}
