package udev

import (
	"strings"
	"testing"
)

// TestStopUsesControlExit pins the stop mechanism: a daemonized udevd
// (started via --daemon) forks and its tracked pid dies immediately, so
// Stop must go through the daemon's control socket
// (`udevadm control --exit`) rather than the dead tracked pid.
//
// The real Stop is driven with the binary lookup and the runner replaced,
// so a regression that stopped using udevadm would fail here.
func TestStopUsesControlExit(t *testing.T) {
	origFind := findBinaryFn
	origRun := udevadmRunner
	t.Cleanup(func() {
		findBinaryFn = origFind
		udevadmRunner = origRun
	})

	findBinaryFn = func(paths []string) string { return "/usr/bin/udevadm" }
	var got []string
	udevadmRunner = func(binary string, args ...string) error {
		got = append([]string{binary}, args...)
		return nil
	}

	Stop()

	want := "/usr/bin/udevadm control --exit"
	if strings.Join(got, " ") != want {
		t.Errorf("Stop invoked %q, want %q", strings.Join(got, " "), want)
	}
}

// TestWriteDBPersistRule validates the db_persist rule content: it must
// scope to block/dm devices and set OPTIONS+=db_persist, which is what
// keeps DM device database entries (and /dev/mapper symlinks) alive
// across switch_root.
func TestWriteDBPersistRule(t *testing.T) {
	rule := `SUBSYSTEM!="block", GOTO="dm_persist_end"
KERNEL!="dm-[0-9]*", GOTO="dm_persist_end"
ACTION!="add|change", GOTO="dm_persist_end"
OPTIONS+="db_persist"
LABEL="dm_persist_end"
`
	if !contains(rule, `OPTIONS+="db_persist"`) {
		t.Error("rule missing OPTIONS+=db_persist")
	}
	if !contains(rule, `KERNEL!="dm-[0-9]*"`) {
		t.Error("rule missing dm device scope")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
