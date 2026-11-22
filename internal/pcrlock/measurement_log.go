package pcrlock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LUKSHeaderDataKey is the CEL data key carrying the measured device path in
// a vanguard-luks-header record.
//
// It exists so the host side can tell the LUKS header records apart: with
// several policy-covered devices the initrd extends PCR 11 once per device,
// and the predicted PCR 11 can only be reconstructed when each record is
// attributed to its device. init/luks/measure.go writes the key at boot.
const LUKSHeaderDataKey = "vanguard-device"

// measurementLogPath is the userspace TPM2 event log written by
// systemd-pcrextend and by vanguard's initrd.
//
// Unlike `systemd-pcrlock cel`, the raw records keep the content of
// unrecognized records — including the vanguard-device tag. The cel output
// strips that content, so a policy with several LUKS devices cannot be
// reconstructed from it.
const measurementLogPath = "/run/log/systemd/tpm2-measure.log"

// measurementLogReader reads the raw measurement log. It is a variable so
// the PCR 11 chain reconstruction can be tested without a real event log.
var measurementLogReader = func() ([]map[string]interface{}, error) {
	data, err := os.ReadFile(measurementLogPath)
	if err != nil {
		return nil, err
	}
	return parseMeasurementLog(data)
}

// parseMeasurementLog parses a JSON-SEQ measurement log: records are
// separated by RS (0x1E), matching systemd-pcrextend's write format.
func parseMeasurementLog(data []byte) ([]map[string]interface{}, error) {
	var events []map[string]interface{}
	for _, raw := range bytes.Split(data, []byte{0x1e}) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var event map[string]interface{}
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

// luksHeaderRecord is one LUKS header measurement in the PCR 11 chain,
// together with the device it was measured from ("" when the log does not
// carry the vanguard-device tag).
type luksHeaderRecord struct {
	digest []byte
	device string
}

// policyRecordIndex returns the index of the LUKS header record that belongs
// to devicePath.
//
// A single record is unambiguous. With several records the device tag is
// required: guessing a position (e.g. "the last one") would replace the wrong
// digest and produce a predicted PCR 11 that does not match the next boot.
func policyRecordIndex(records []luksHeaderRecord, devicePath string) (int, error) {
	if len(records) == 0 {
		return -1, fmt.Errorf("no LUKS header records in the event log")
	}
	if len(records) == 1 {
		return 0, nil
	}
	for i, rec := range records {
		if sameDevice(rec.device, devicePath) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("cannot attribute a LUKS header measurement to %s among %d measured devices — refusing to guess the PCR 11 chain (boot once with the current initrd so all devices are measured, then re-run vanguard update)", devicePath, len(records))
}

// sameDevice compares two device paths, resolving symlinks on both sides.
// The initrd records the path it discovered (e.g. /dev/nvme0n1p2), while the
// operator may pass a symlink such as /dev/disk/by-uuid/... — a plain string
// comparison would refuse a legitimate match.
func sameDevice(a, b string) bool {
	if a == b {
		return true
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// eventDeviceTag returns the device a measurement record was taken from, or
// "" when the record carries no vanguard-device tag.
func eventDeviceTag(event map[string]interface{}) string {
	content, ok := event["content"].(map[string]interface{})
	if !ok {
		return ""
	}
	data, ok := content["data"].(map[string]interface{})
	if !ok {
		return ""
	}
	device, _ := data[LUKSHeaderDataKey].(string)
	return device
}
