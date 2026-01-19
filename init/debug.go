//go:build debug

package main

import "github.com/zaolin/vanguard/init/console"

// debugEnabled indicates whether debug output is enabled
const debugEnabled = true

// debug prints a message only when debug mode is enabled
func debug(format string, args ...any) {
	console.Print(format, args...)
}
