package main

import (
	"os"
	"testing"
)

// TestMain makes platform readers deterministic for the whole package:
// buildThreatModel must not depend on the host's swap or suspend
// configuration. Individual exposure tests override the readers with their own
// fixtures and restore them via t.Cleanup.
func TestMain(m *testing.M) {
	swapsReader = func() ([]swapEntry, error) { return nil, nil }
	sleepStateReader = func() (string, string, error) { return "", "", nil }
	os.Exit(m.Run())
}
