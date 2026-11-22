package pcrlock

import (
	"os"
	"testing"
)

// TestPolicyRecordIndex pins which LUKS header record is replaced when the
// policy is regenerated. Guessing a position would produce a predicted
// PCR 11 that does not match the next boot on a multi-device system.
func TestPolicyRecordIndex(t *testing.T) {
	devA := []byte{0x01}
	devB := []byte{0x02}
	devC := []byte{0x03}

	tests := []struct {
		name     string
		records  []luksHeaderRecord
		device   string
		wantIdx  int
		wantFail bool
	}{
		{
			name:    "a single record is unambiguous without a tag",
			records: []luksHeaderRecord{{digest: devA}},
			device:  "/dev/nvme0n1p2",
			wantIdx: 0,
		},
		{
			name: "the tagged record is chosen, not the last one",
			records: []luksHeaderRecord{
				{digest: devA, device: "/dev/nvme0n1p2"},
				{digest: devB, device: "/dev/sda1"},
			},
			device:  "/dev/nvme0n1p2",
			wantIdx: 0,
		},
		{
			name: "the policy device may be the last one too",
			records: []luksHeaderRecord{
				{digest: devA, device: "/dev/nvme0n1p2"},
				{digest: devB, device: "/dev/sda1"},
			},
			device:  "/dev/sda1",
			wantIdx: 1,
		},
		{
			name: "three devices, policy device in the middle",
			records: []luksHeaderRecord{
				{digest: devA, device: "/dev/nvme0n1p2"},
				{digest: devB, device: "/dev/sda1"},
				{digest: devC, device: "/dev/sdb1"},
			},
			device:  "/dev/sda1",
			wantIdx: 1,
		},
		{
			name: "no tags at all is refused instead of guessed",
			records: []luksHeaderRecord{
				{digest: devA},
				{digest: devB},
			},
			device:   "/dev/nvme0n1p2",
			wantFail: true,
		},
		{
			name: "an unknown device is refused",
			records: []luksHeaderRecord{
				{digest: devA, device: "/dev/nvme0n1p2"},
				{digest: devB, device: "/dev/sda1"},
			},
			device:   "/dev/sdb1",
			wantFail: true,
		},
		{
			name:     "no records is an error",
			records:  nil,
			device:   "/dev/nvme0n1p2",
			wantFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := policyRecordIndex(tc.records, tc.device)
			if tc.wantFail {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("policyRecordIndex: %v", err)
			}
			if idx != tc.wantIdx {
				t.Errorf("index = %d, want %d", idx, tc.wantIdx)
			}
		})
	}
}

// TestParseMeasurementLog pins the JSON-SEQ parsing of the raw measurement
// log: records are RS-separated and keep their content, which is where the
// device tag lives.
func TestParseMeasurementLog(t *testing.T) {
	data := []byte("\x1e{\"pcr\":11,\"digests\":[],\"content\":{\"data\":{\"vanguard-device\":\"/dev/nvme0n1p2\"}}}\n" +
		"\x1e{\"pcr\":11,\"digests\":[],\"content\":{\"data\":{\"vanguard-device\":\"/dev/sda1\"}}}\n")

	events, err := parseMeasurementLog(data)
	if err != nil {
		t.Fatalf("parseMeasurementLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("parsed %d events, want 2", len(events))
	}
	if got := eventDeviceTag(events[0]); got != "/dev/nvme0n1p2" {
		t.Errorf("device tag = %q, want /dev/nvme0n1p2", got)
	}
	if got := eventDeviceTag(events[1]); got != "/dev/sda1" {
		t.Errorf("device tag = %q, want /dev/sda1", got)
	}
}

// TestSameDeviceResolvesSymlinks pins that a device given by a symlink (e.g.
// /dev/disk/by-uuid/...) matches the path the initrd recorded.
func TestSameDeviceResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := dir + "/nvme0n1p2"
	if err := os.WriteFile(target, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	link := dir + "/by-uuid-link"
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}

	if !sameDevice(link, target) {
		t.Error("a symlink and its target must be the same device")
	}
	if !sameDevice(target, target) {
		t.Error("identical paths must match")
	}
	if sameDevice(link, dir+"/other") {
		t.Error("different devices must not match")
	}
	// Paths that do not exist cannot be resolved: only a literal match is
	// accepted then.
	if sameDevice(dir+"/missing-a", dir+"/missing-b") {
		t.Error("two different nonexistent paths must not match")
	}
}

// TestPolicyRecordIndexUsesSymlinkIdentity pins the attribution with a
// symlinked policy device.
func TestPolicyRecordIndexUsesSymlinkIdentity(t *testing.T) {
	dir := t.TempDir()
	target := dir + "/nvme0n1p2"
	if err := os.WriteFile(target, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	link := dir + "/by-uuid-link"
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}

	records := []luksHeaderRecord{
		{digest: []byte{0x01}, device: target},
		{digest: []byte{0x02}, device: dir + "/sda1"},
	}
	idx, err := policyRecordIndex(records, link)
	if err != nil {
		t.Fatalf("policyRecordIndex: %v", err)
	}
	if idx != 0 {
		t.Errorf("index = %d, want 0 (the symlinked policy device)", idx)
	}
}

// TestEventDeviceTagMissing pins that a record without the tag yields an
// empty device rather than a wrong one.
func TestEventDeviceTagMissing(t *testing.T) {
	if got := eventDeviceTag(map[string]interface{}{"pcr": 11.0}); got != "" {
		t.Errorf("device tag = %q, want empty", got)
	}
}
