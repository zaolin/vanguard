package buildtags

// StrictMode enforces token-only unlock with no passphrase fallback.
// Always true — strict mode is the default and only mode.
// Passphrase fallback requires TOTP recovery (see init/recovery/recovery.go).
const StrictMode = true
