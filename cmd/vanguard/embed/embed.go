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

// InitStrictBinary contains the pre-built init binary (strict mode, token-only unlock)
//
//go:embed init-strict
var InitStrictBinary []byte

// InitDebugStrictBinary contains the pre-built init binary (debug + strict mode)
//
//go:embed init-debug-strict
var InitDebugStrictBinary []byte
