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
	var seed []byte
	var refTimestamp int64
	seed, refTimestamp, _, err := tpmClient.ReadRecoveryData(intpm.DefaultRecoverySeedNVIndex)
	if err != nil {
		// ReadRecoveryData failed. Check if it's because the timestamp NV
		// index is missing (e.g., from a previous failed auto-reseed).
		// If so, try reading the seed without the timestamp.
		if !tpmClient.TimestampNVExists() {
			buildtags.Debug("recovery: timestamp NV index missing, trying seed-only read\n")
			seed, err = tpmClient.ReadSeedOnly(intpm.DefaultRecoverySeedNVIndex)
			if err != nil {
				console.Print("recovery: failed to read TOTP seed from TPM: %v\n", err)
				LogFunc("RECOVERY_READ_FAIL", "device", devicePath, "error", err.Error())
				return false
			}
			// No reference timestamp available — use current time as reference
			// with wide skew. This is safe because the TOTP seed is TPM-protected.
			refTimestamp = time.Now().Unix()
			console.Print("recovery: WARNING: timestamp NV index missing, using current time as reference\n")
			LogFunc("RECOVERY_TIMESTAMP_MISSING", "device", devicePath)
		} else {
			console.Print("recovery: failed to read TOTP seed from TPM: %v\n", err)
			LogFunc("RECOVERY_READ_FAIL", "device", devicePath, "error", err.Error())
			return false
		}
	}
	// Zero the seed after use to reduce cold-boot extraction window
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	// 3. Check RTC sanity
	now := time.Now()
	refTime := time.Unix(refTimestamp, 0)
	rtcDrifted := abs(now.Unix()-refTimestamp) > RTCDriftThreshold
	if rtcDrifted {
		console.Print("recovery: WARNING: clock may be wrong (ref=%d, rtc=%d)\n",
			refTimestamp, now.Unix())
		console.Print("recovery: Enter the current TOTP code from your authenticator app.\n")
		console.Print("recovery: If your code is rejected, the system clock may need resetting after boot.\n")
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
		// When RTC is correct, use normal skew (±90s).
		// When RTC has drifted, also try the reference timestamp with
		// wide skew (±24h) — the user's authenticator app uses real
		// current time, which should be within ±24h of the last boot.
		var valid bool
		if rtcDrifted {
			valid = totp.ValidateWithDrift(code, seed, now, uint(totp.DriftSkew), refTime)
		} else {
			valid = totp.Validate(code, seed, now, uint(totp.DefaultSkew))
		}

		if valid {
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
	console.Print("recovery: if your system clock is wrong, boot a live USB and run:\n")
	console.Print("recovery:   sudo timedatectl set-ntp true\n")
	console.Print("recovery:   sudo hwclock --systohc\n")
	return false
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
