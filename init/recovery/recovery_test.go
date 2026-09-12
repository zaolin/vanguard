package recovery

import (
	"testing"
)

// TestAttemptConstants validates the recovery attempt/fail bounds.
func TestAttemptConstants(t *testing.T) {
	if MaxHOTPAttempts < 1 {
		t.Error("MaxHOTPAttempts must be >= 1")
	}
	if MaxFailCount <= MaxHOTPAttempts {
		t.Error("MaxFailCount should exceed a single boot's attempt budget")
	}
}

// TestFailCountLockBoundary documents the lock threshold: failCount values at
// or above MaxFailCount must gate recovery.
func TestFailCountLockBoundary(t *testing.T) {
	locked := func(failCount uint32) bool { return failCount >= MaxFailCount }
	if !locked(MaxFailCount) {
		t.Error("failCount == MaxFailCount must be locked")
	}
	if !locked(MaxFailCount + 1) {
		t.Error("failCount > MaxFailCount must be locked")
	}
	if locked(MaxFailCount - 1) {
		t.Error("failCount just below MaxFailCount must not be locked")
	}
	if locked(0) {
		t.Error("failCount 0 must not be locked")
	}
}
