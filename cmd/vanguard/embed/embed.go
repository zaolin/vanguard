package embed

import _ "embed"

// InitBinary contains the pre-built init binary (release mode, minimal output)
// Strict mode is always-on (no passphrase fallback without TOTP recovery)
//
//go:embed init
var InitBinary []byte

// InitDebugBinary contains the pre-built init binary (debug mode, verbose output)
// Strict mode is always-on (no passphrase fallback without TOTP recovery)
//
//go:embed init-debug
var InitDebugBinary []byte
