package luks

import (
	"strings"
	"testing"
)

// TestCELRecordCarriesDevicePath pins that the measured device path is
// written into the event log record.
//
// With several LUKS devices the initrd extends PCR 11 once per
// policy-covered device, forming a hash chain. The host side needs the
// device identity to keep the records apart and reproduce the measurement
// order — without it, "the first record" and "the last record" could be
// different devices and the policy's predicted PCR 11 would not match
// what the next boot computes.
func TestCELRecordCarriesDevicePath(t *testing.T) {
	digest := []byte{0x01, 0x02, 0x03, 0x04}
	raw, err := buildCELRecord(11, digest, "/dev/nvme0n1p2")
	if err != nil {
		t.Fatalf("buildCELRecord: %v", err)
	}

	s := string(raw)
	if !strings.Contains(s, LUKSHeaderDataKey) {
		t.Errorf("record does not contain the device key %q: %s", LUKSHeaderDataKey, s)
	}
	if !strings.Contains(s, "/dev/nvme0n1p2") {
		t.Errorf("record does not contain the device path: %s", s)
	}
	// The pre-existing marker must stay — the host side identifies our
	// records by the absence of a known content_type.
	if !strings.Contains(s, "vanguard-luks-header") {
		t.Errorf("record lost the vanguard-luks-header marker: %s", s)
	}
}

// TestCELRecordWithoutDevicePath verifies the device key is optional
// (older records and direct calls stay valid).
func TestCELRecordWithoutDevicePath(t *testing.T) {
	raw, err := buildCELRecord(11, []byte{0x01}, "")
	if err != nil {
		t.Fatalf("buildCELRecord: %v", err)
	}
	if strings.Contains(string(raw), LUKSHeaderDataKey) {
		t.Errorf("record should not contain the device key when no path is given: %s", string(raw))
	}
}
