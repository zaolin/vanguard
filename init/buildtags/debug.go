//go:build debug

package buildtags

import "github.com/zaolin/vanguard/init/console"

// DebugEnabled indicates whether debug output is enabled
const DebugEnabled = true

// Debug prints a message only when debug mode is enabled
func Debug(format string, args ...any) {
	console.Print(format, args...)
}
