// Package recovery implements TOTP-based boot recovery for Vanguard.
// When the TPM2 unseal fails in strict mode, the user can enter a
// TOTP code from their authenticator app to authorize passphrase
// fallback for this boot only.
package recovery

import (
	"fmt"
	"time"

	"github.com/zaolin/vanguard/init/buildtags"
	"github.com/zaolin/vanguard/init/console"
	"github.com/zaolin/vanguard/internal/totp"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// MaxTOTPAttempts is the maximum number of TOTP code attempts before halting.
const MaxTOTPAttempts = 3

// RTCDriftThreshold is the maximum allowed difference between the RTC
// and the reference timestamp before we switch to drift-tolerant skew.
// 300 seconds = 5 minutes.
const RTCDriftThreshold = 300

// LogFunc is a callback for boot logging, set by the caller.
var LogFunc func(event string, kvPairs ...string) = func(event string, kvPairs ...string) {}

// TryTOTP attempts TOTP-based recovery when TPM unseal fails in strict mode.
// It reads the TOTP seed from TPM NVRAM, prompts the user for a 6-digit code,
// and validates it. If successful, the caller should enable passphrase fallback.
//
// Returns true if recovery succeeded (passphrase fallback should be enabled),
// false if recovery is not configured or all attempts failed.
func TryTOTP(tpmClient *intpm.Client, devicePath string) bool {
	// 1. Check if recovery NV index exists
	if !tpmClient.RecoveryNVExists(intpm.DefaultRecoverySeedNVIndex) {
		buildtags.Debug("recovery: no TOTP recovery configured (NV index not found)\n")
		return false
	}

	// 2. Read seed + reference timestamp + enrollment branch digest
	// The seed is read via a policy session that requires the current PCR 7
	// value to match the anti-evil-maid policy (Secure Boot state). If the
	// system was booted from a live USB or the initrd was tampered with,
	// the PCR 7 value won't match and the read will fail.
	//
	// The enrollment-time branch digest is also read (from the timestamp
	// NV index) for API compatibility, though with the single-branch
	// PolicyPCR design it is not used at runtime — the session digest
	// after PolicyPCR directly matches the authPolicy.
	seed, refTimestamp, _, err := tpmClient.ReadRecoveryData(intpm.DefaultRecoverySeedNVIndex)
	if err != nil {
		console.Print("recovery: failed to read TOTP seed from TPM: %v\n", err)
		LogFunc("RECOVERY_READ_FAIL", "device", devicePath, "error", err.Error())
		return false
	}
	// Zero the seed after use to reduce cold-boot extraction window
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	// 3. Check RTC sanity
	now := time.Now()
	skew := uint(totp.DefaultSkew)
	if abs(now.Unix()-refTimestamp) > RTCDriftThreshold {
		skew = uint(totp.DriftSkew)
		console.Print("recovery: WARNING: clock may be wrong (ref=%d, rtc=%d) — using ±5min tolerance\n",
			refTimestamp, now.Unix())
		LogFunc("RECOVERY_RTC_DRIFT", "device", devicePath,
			"ref", fmt.Sprintf("%d", refTimestamp), "rtc", fmt.Sprintf("%d", now.Unix()))
	}

	// 4. Prompt for TOTP code (up to MaxTOTPAttempts)
	for attempt := 1; attempt <= MaxTOTPAttempts; attempt++ {
		console.Print("\n")
		console.Print("vanguard: TPM unlock failed. Enter recovery TOTP code (attempt %d of %d):\n",
			attempt, MaxTOTPAttempts)

		// Read the code from console (echo disabled for security)
		code, err := console.ReadPassword("Recovery code: ")
		if err != nil {
			console.Print("recovery: failed to read code: %v\n", err)
			return false
		}

		// 5. Validate TOTP
		if totp.Validate(code, seed, now, skew) {
			console.Print("recovery: TOTP code accepted — passphrase fallback enabled for this boot\n")
			LogFunc("RECOVERY_TOTP", "device", devicePath, "status", "ok")

			// 6. Update reference timestamp for next boot
			if err := tpmClient.UpdateRecoveryTimestamp(now.Unix()); err != nil {
				buildtags.Debug("recovery: warning: failed to update reference timestamp: %v\n", err)
			}

			return true
		}

		console.Print("recovery: invalid TOTP code\n")
		LogFunc("RECOVERY_TOTP_FAIL", "device", devicePath,
			"attempt", fmt.Sprintf("%d", attempt))
	}

	console.Print("recovery: too many failed TOTP attempts\n")
	return false
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
