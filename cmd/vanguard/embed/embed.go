package embed

import _ "embed"

// InitBinary contains the pre-built init binary (release mode, minimal output)
//
//go:embed init
var InitBinary []byte

// InitDebugBinary contains the pre-built init binary (debug mode, verbose output)
//
//go:embed init-debug
var InitDebugBinary []byte
