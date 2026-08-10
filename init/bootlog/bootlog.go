package bootlog

import (
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	logPath    = "/boot/.vanguard.log"
	sessionSep = "================================================================================"
)

// Event types for structured logging
type Event string

const (
	EventBootStart          Event = "BOOT_START"
	EventEssentialMounts    Event = "ESSENTIAL_MOUNTS"
	EventModulesLoaded      Event = "MODULES_LOADED"
	EventBootMounted        Event = "BOOT_MOUNTED"
	EventPCRLock            Event = "PCRLOCK"
	EventLUKSUnlock         Event = "LUKS_UNLOCK"
	EventLUKSFail           Event = "LUKS_FAIL"
	EventTPMUnavailable     Event = "TPM_UNAVAILABLE"
	EventPassphraseFallback Event = "PASSPHRASE_FALLBACK"
	EventLVMActivate        Event = "LVM_ACTIVATE"
	EventRootMounted        Event = "ROOT_MOUNTED"
	EventSwitchroot         Event = "SWITCHROOT"
	EventDebug              Event = "DEBUG"
)

var (
	mu          sync.Mutex
	buffer      []string
	initialized bool
)

// remountRW and remountRO are function variables so they can be overridden
// in tests. By default they use unix.Mount to remount /boot.
var (
	remountRW = func() error { return unix.Mount("", "/boot", "", unix.MS_REMOUNT, "") }
	remountRO = func() error { return unix.Mount("", "/boot", "", unix.MS_REMOUNT|unix.MS_RDONLY, "") }
)

// Init initializes the boot log for a new session.
// Lines are buffered in memory — no file operations or remounts happen
// until Close() is called. This keeps /boot read-only for the entire
// boot sequence, eliminating the TOCTOU window from repeated remounts.
func Init() error {
	mu.Lock()
	defer mu.Unlock()

	if initialized {
		return nil
	}

	// Record session start time
	sessionTime := time.Now().UTC()

	// Write session header to the in-memory buffer
	header := fmt.Sprintf("\n%s\nVANGUARD BOOT LOG - %s\n%s\n\n",
		sessionSep,
		sessionTime.Format(time.RFC3339),
		sessionSep)

	buffer = append(buffer, header)
	initialized = true
	return nil
}

// Log appends an event with optional key-value data to the in-memory buffer.
// No file I/O or remounts happen — the buffer is flushed to /boot only
// when Close() is called.
// Example: Log(EventLUKSUnlock, "device", "/dev/sda2", "method", "tpm2")
func Log(event Event, kvPairs ...string) error {
	mu.Lock()
	defer mu.Unlock()

	if !initialized {
		return fmt.Errorf("log not initialized")
	}

	// Format timestamp with millisecond precision
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	// Build log line
	line := fmt.Sprintf("[%s] %s", ts, event)

	// Append key-value pairs
	if len(kvPairs) >= 2 {
		line += ":"
		for i := 0; i+1 < len(kvPairs); i += 2 {
			if i > 0 {
				line += ","
			}
			line += fmt.Sprintf(" %s=%s", kvPairs[i], kvPairs[i+1])
		}
	}
	line += "\n"

	buffer = append(buffer, line)
	return nil
}

// Close flushes all buffered log lines to /boot/.vanguard.log.
// This is the ONLY point where /boot is remounted read-write:
//  1. Remount /boot RW
//  2. Open log file (create/append)
//  3. Write all buffered lines at once
//  4. Sync and close
//  5. Remount /boot RO
//
// Must be called before switchroot. If /boot is not mounted or the
// remount fails, the buffered log is silently discarded (the boot
// has already succeeded by this point).
func Close() error {
	mu.Lock()
	defer mu.Unlock()

	if !initialized {
		return nil
	}

	// Clear state regardless of whether the write succeeds
	defer func() {
		buffer = nil
		initialized = false
	}()

	// Remount /boot read-write for the single write
	if err := remountRW(); err != nil {
		// /boot might not be mounted, or remount failed — silently discard
		return nil
	}

	// Ensure we remount RO when done
	defer func() { _ = remountRO() }()

	// Open log file (create if not exists, append mode, sync writes)
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0644)
	if err != nil {
		return nil // silently discard — boot has succeeded
	}
	defer f.Close()

	// Write all buffered lines at once
	for _, line := range buffer {
		if _, err := f.WriteString(line); err != nil {
			break // best-effort — stop on first error
		}
	}

	f.Sync()
	return nil
}
