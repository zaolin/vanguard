package bootlog

import (
	"fmt"
	"os"
	"sync"
	"time"
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
	logFile     *os.File
	logMu       sync.Mutex
	initialized bool
)

// Init initializes the boot log for a new session.
// It opens the log file in append mode and writes the session header.
// Returns error if initialization fails (caller should ignore and continue boot).
func Init() error {
	logMu.Lock()
	defer logMu.Unlock()

	if initialized {
		return nil
	}

	// Open log file (create if not exists, append mode, sync writes)
	var err error
	logFile, err = os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0644)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}

	// Record session start time
	sessionTime := time.Now().UTC()

	// Write session header
	header := fmt.Sprintf("\n%s\nCRYPTINT BOOT LOG - %s\n%s\n\n",
		sessionSep,
		sessionTime.Format(time.RFC3339),
		sessionSep)

	if _, err := logFile.WriteString(header); err != nil {
		logFile.Close()
		logFile = nil
		return fmt.Errorf("write header: %w", err)
	}

	initialized = true
	return nil
}

// Log writes an event with optional key-value data.
// Example: Log(EventLUKSUnlock, "device", "/dev/sda2", "method", "tpm2")
// Returns error if write fails (caller should ignore and continue boot).
func Log(event Event, kvPairs ...string) error {
	logMu.Lock()
	defer logMu.Unlock()

	if logFile == nil {
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

	// Write to file (O_SYNC ensures durability)
	if _, err := logFile.WriteString(line); err != nil {
		return fmt.Errorf("write log: %w", err)
	}

	return nil
}

// Close flushes and closes the log file.
// Must be called before switchroot.
func Close() error {
	logMu.Lock()
	defer logMu.Unlock()

	if logFile == nil {
		return nil
	}

	// Sync and close
	logFile.Sync()
	logFile.Close()
	logFile = nil
	initialized = false

	return nil
}
