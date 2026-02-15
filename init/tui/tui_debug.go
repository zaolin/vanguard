//go:build debug

package tui

// In debug mode, TUI is disabled - all functions are no-ops

// Boot stage names (same as in tui.go, needed for compilation)
const (
	StageConsole    = "Initializing console"
	StageMounting   = "Mounting filesystems"
	StageVConsole   = "Configuring vconsole"
	StageUdev       = "Starting udev"
	StageModules    = "Loading kernel modules"
	StageTPM        = "Loading TPM modules"
	StagePCRLock    = "Setting up pcrlock"
	StageLUKS       = "Unlocking encrypted devices"
	StageLVM        = "Activating LVM volumes"
	StageResume     = "Checking hibernate resume"
	StageRoot       = "Mounting root filesystem"
	StageFsck       = "Checking filesystem"
	StageSwitchroot = "Switching to root"
)

// Start is a no-op in debug mode
func Start() error {
	return nil
}

// UpdateStage is a no-op in debug mode
func UpdateStage(stage string) {}

// StageDone is a no-op in debug mode
func StageDone(stage string) {}

// StageError is a no-op in debug mode
func StageError(stage string, err error) {}

// PromptPassword returns an error in debug mode - use console.ReadPassword instead
func PromptPassword(device string) (string, error) {
	return "", nil // Will fall back to console
}

// PasswordError is a no-op in debug mode
func PasswordError(msg string) {}

// PasswordErrorWithRetry returns empty in debug mode - use console.ReadPassword for retries
func PasswordErrorWithRetry(msg string) (string, error) {
	return "", nil
}

// PasswordPromptDone is a no-op in debug mode
func PasswordPromptDone() {}

// ShowTPMLockout is a no-op in debug mode
func ShowTPMLockout(message, recoveryHint string) {}

// ShowTPMError is a no-op in debug mode
func ShowTPMError(message string) {}

// Quit is a no-op in debug mode
func Quit() {}

// ForceReset is a no-op in debug mode
func ForceReset() {}

// IsEnabled returns false in debug mode
func IsEnabled() bool {
	return false
}
