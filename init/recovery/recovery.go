// Package recovery implements HOTP-based boot recovery for Vanguard.
// When the TPM2 unseal fails in strict mode, the user can enter a
// counter-based one-time code from their authenticator app to authorize
// passphrase fallback for this boot only.
//
// HOTP (RFC 4226) is used instead of TOTP (RFC 6238) because the initramfs
// has no trustworthy clock: the RTC may be reset (dead CMOS battery,
// firmware update) and there is no network for NTP. HOTP validates against
// a counter persisted in TPM NVRAM, so it is immune to clock drift.
package recovery

import (
	"fmt"

	"github.com/zaolin/vanguard/init/buildtags"
	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/internal/hotp"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// MaxHOTPAttempts is the maximum number of HOTP code attempts per boot.
const MaxHOTPAttempts = 3

// MaxFailCount caps the lifetime number of failed HOTP attempts. Once the
// persisted fail counter reaches this value, recovery refuses further codes
// (even a correct one) until the counter is reset by a successful disk
// unlock. This bounds cross-boot online guessing: without it, an attacker
// could reboot indefinitely and get MaxHOTPAttempts fresh guesses each boot.
const MaxFailCount = 10

// LogFunc is a callback for boot logging, set by the caller.
var LogFunc func(event string, kvPairs ...string) = func(event string, kvPairs ...string) {}

// TryHOTP attempts HOTP-based recovery when TPM unseal fails in strict mode.
// It reads the HOTP seed and counter from TPM NVRAM, prompts the user for a
// 8-digit code, validates it against the counter lookahead window, and on
// success advances the stored counter past the matched position so the code
// can never be reused.
//
// Returns true if recovery succeeded (passphrase fallback should be enabled).
func TryHOTP(tpmClient *intpm.Client, devicePath string) bool {
	// 1. Check if recovery is provisioned (seed index exists).
	if !tpmClient.RecoveryNVExists(intpm.DefaultRecoverySeedNVIndex) {
		buildtags.Debug("recovery: no HOTP recovery configured (seed NV index not found)\n")
		return false
	}

	// 2. Distinguish a legacy TOTP enrollment (seed present, state index
	// missing) BEFORE the generic read failure: ReadRecoveryData would fail
	// on the missing state index and the user would see an opaque TPM error
	// with no guidance.
	if !tpmClient.StateNVExists() {
		console.Print("recovery: HOTP recovery is NOT provisioned for this vanguard version\n")
		console.Print("recovery: (legacy TOTP enrollment detected — seed present but state index missing)\n")
		console.Print("recovery: boot the installed system and run: sudo vanguard recovery --enable\n")
		LogFunc("RECOVERY_LEGACY_STATE_MISSING", "device", devicePath)
		return false
	}

	// 3. Read the seed (PCR 7-bound) and the counter/fail state (policy auth).
	var seed []byte
	var counter uint64
	var failCount uint32
	seed, counter, failCount, err := tpmClient.ReadRecoveryData(intpm.DefaultRecoverySeedNVIndex)
	if err != nil {
		console.Print("recovery: failed to read HOTP recovery data from TPM: %v\n", err)
		LogFunc("RECOVERY_READ_FAIL", "device", devicePath, "error", err.Error())
		return false
	}
	// Zero the seed after use to reduce cold-boot extraction window
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	// 4. Refuse if the persistent fail cap is reached. A successful disk
	// unlock resets the counter; until then, offline attackers cannot gain
	// fresh guesses by rebooting.
	if failCount >= MaxFailCount {
		console.Print("recovery: recovery is locked after %d failed attempts\n", failCount)
		console.Print("recovery: the failure counter resets automatically after a successful\n")
		console.Print("recovery: disk unlock; otherwise boot a live USB to unlock with your passphrase\n")
		LogFunc("RECOVERY_LOCKED", "device", devicePath, "fail_count", fmt.Sprintf("%d", failCount))
		return false
	}

	// 5. Prompt for the code (up to MaxHOTPAttempts this boot).
	for attempt := 1; attempt <= MaxHOTPAttempts; attempt++ {
		console.Print("\n")
		console.Print("vanguard: TPM unlock failed. Enter recovery HOTP code (attempt %d of %d):\n",
			attempt, MaxHOTPAttempts)

		code, err := console.ReadPassword("Recovery code: ")
		if err != nil {
			console.Print("recovery: failed to read code: %v\n", err)
			return false
		}

		matched, ok := hotp.Validate(code, seed, counter, hotp.Lookahead)
		console.ZeroString(&code)
		if ok {
			// Advance the counter past the matched position so this code
			// (and every earlier one) is consumed, then clear the fail
			// count.
			if err := tpmClient.WriteRecoveryState(matched+1, 0); err != nil {
				// The code was valid; failing to persist the counter means
				// the same code could be replayed next boot, but recovery
				// itself should still proceed.
				buildtags.Debug("recovery: warning: failed to persist counter: %v\n", err)
				LogFunc("RECOVERY_COUNTER_PERSIST_FAIL", "device", devicePath, "error", err.Error())
			}
			console.Print("recovery: HOTP code accepted — passphrase fallback enabled for this boot\n")
			LogFunc("RECOVERY_HOTP", "device", devicePath, "status", "ok")
			return true
		}

		failCount++
		// Persist the incremented fail count (best effort — never block recovery).
		if werr := tpmClient.WriteRecoveryState(counter, failCount); werr != nil {
			buildtags.Debug("recovery: warning: failed to persist fail count: %v\n", werr)
		}
		console.Print("recovery: invalid HOTP code\n")
		LogFunc("RECOVERY_HOTP_FAIL", "device", devicePath,
			"attempt", fmt.Sprintf("%d", attempt), "fail_count", fmt.Sprintf("%d", failCount))

		if failCount >= MaxFailCount {
			console.Print("recovery: failure cap reached (%d) — recovery is now locked until a successful unlock\n", MaxFailCount)
			LogFunc("RECOVERY_LOCKED", "device", devicePath, "fail_count", fmt.Sprintf("%d", failCount))
			return false
		}
	}

	console.Print("recovery: too many failed HOTP attempts this boot\n")
	return false
}

// ResetFailCount clears the persisted failure counter. Called after a
// successful disk unlock so a legitimate user's earlier typos do not count
// against future recovery attempts. Best-effort.
func ResetFailCount(tpmClient *intpm.Client) {
	if !tpmClient.StateNVExists() {
		return
	}
	counter, failCount, err := tpmClient.ReadRecoveryState()
	if err != nil {
		return
	}
	if failCount == 0 {
		return
	}
	if err := tpmClient.WriteRecoveryState(counter, 0); err != nil {
		buildtags.Debug("recovery: warning: failed to reset fail count: %v\n", err)
		return
	}
	LogFunc("RECOVERY_FAILCOUNT_RESET", "status", "ok")
}
