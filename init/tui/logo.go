//go:build !debug

package tui

import _ "embed"

//go:embed logo.txt
var Logo string

//go:embed title.txt
var Title string
