package luks

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zaolin/vanguard/init/buildtags"
	"github.com/zaolin/vanguard/init/console"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// PCRUsedForLUKSHeader is the PCR index that the LUKS header hash is extended into.
// PCR 11 is the boot-phase PCR used by systemd for enter-initrd/leave-initrd/sysinit/ready.
// Vanguard's custom init does not extend these phase markers, so PCR 11 at LUKS unlock
// time contains only the sd-stub kernel measurement (if present) plus our LUKS header
// extension. The pcrlock policy predicts this value via a custom component file
// (755-vanguard-luks-header.pcrlock) created during `vanguard update`.
const PCRUsedForLUKSHeader = 11

// eventLogPath is the userspace TPM2 event log maintained by systemd-pcrextend.
// systemd-pcrlock reads this file (combined with the firmware event log) to predict
// future PCR values. We write CEL-JSON records here so make-policy can match our
// LUKS header measurement component.
var eventLogPath = "/run/log/systemd/tpm2-measure.log"

// MeasureHeader hashes the LUKS2 header, extends PCR 11 with the hash, and writes
// a CEL-JSON record to the userspace event log. This binds the pcrlock policy to
// the on-disk LUKS header state.
//
// Must be called BEFORE Unlock() so the PCR value at unseal time includes the
// header measurement. Called once per LUKS device; each call extends PCR 11
// further (hash chain).
//
// All errors are non-fatal: if the TPM is unavailable, the header can't be
// hashed, or the PCR extend fails, the measurement is skipped and the boot
// continues. The pcrlock policy will simply not include PCR 11 in this case.
func (d *Device) MeasureHeader() error {
	return measureHeaderWithDeps(d.Path, intpm.New, writeEventLogRecord)
}

// measureHeaderWithDeps is the testable core of MeasureHeader. It accepts
// injected dependencies for the TPM client factory and event log writer.
func measureHeaderWithDeps(
	devicePath string,
	newTPMClient func() *intpm.Client,
	writeEventLog func(int, []byte) error,
) error {
	digest, err := HashLUKS2Header(devicePath)
	if err != nil {
		buildtags.Debug("luks: failed to hash LUKS2 header for measurement: %v\n", err)
		return nil
	}

	// Extend PCR 11 with the header hash
	tpmClient := newTPMClient()
	if !tpmClient.WaitForDevice(3e9) {
		buildtags.Debug("luks: TPM not available for header measurement, skipping\n")
		return nil
	}

	if err := tpmClient.ExtendPCR(PCRUsedForLUKSHeader, intpm.AlgSHA256, digest); err != nil {
		buildtags.Debug("luks: PCR %d extend failed: %v\n", PCRUsedForLUKSHeader, err)
		return nil
	}

	console.DebugPrint("luks: measured LUKS2 header into PCR %d (hash: %s)\n",
		PCRUsedForLUKSHeader, hex.EncodeToString(digest))

	// Write CEL-JSON record to the userspace event log so systemd-pcrlock
	// make-policy can match it against our .pcrlock component file.
	if err := writeEventLog(PCRUsedForLUKSHeader, digest); err != nil {
		buildtags.Debug("luks: failed to write event log record: %v\n", err)
	}

	return nil
}

// celRecord is a minimal CEL-JSON record matching the format used by
// systemd-pcrextend. The "content" and "content_type" fields are included
// for compatibility but are ignored by systemd-pcrlock's component matching
// (only "pcr" and "digests" are used, per systemd.pcrlock(5)).
type celRecord struct {
	PCR       int         `json:"pcr"`
	Digests   []celDigest `json:"digests"`
	Content   celContent  `json:"content"`
	ContentType string     `json:"content_type"`
}

type celDigest struct {
	HashAlg string `json:"hashAlg"`
	Digest  string `json:"digest"`
}

type celContent struct {
	EventType string `json:"event_type"`
	Data      map[string]string `json:"data"`
}

// writeEventLogRecord appends a CEL-JSON record to the userspace TPM2 event log
// at /run/log/systemd/tpm2-measure.log. The file uses JSON-SEQ format: records
// are separated by RS (0x1E). An exclusive BSD flock is acquired to ensure
// atomic writes, matching systemd-pcrextend's behavior.
func writeEventLogRecord(pcr int, digest []byte) error {
	// Ensure the directory exists
	dir := filepath.Dir(eventLogPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create event log directory: %w", err)
	}

	data, err := buildCELRecord(pcr, digest)
	if err != nil {
		return err
	}

	// Open with O_APPEND|O_CREAT, acquire exclusive flock
	f, err := os.OpenFile(eventLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open event log: %w", err)
	}
	defer f.Close()

	// Acquire exclusive lock (LOCK_EX)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock event log: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	// Write the record using the locked file handle
	if err := writeCELData(f, data); err != nil {
		return err
	}

	buildtags.Debug("luks: wrote CEL record to %s (pcr=%d, digest=%s)\n",
		eventLogPath, pcr, hex.EncodeToString(digest))
	return nil
}

// buildCELRecord constructs the CEL-JSON record bytes for the given PCR and
// digest. Separated from writeEventLogRecord for testability.
func buildCELRecord(pcr int, digest []byte) ([]byte, error) {
	record := celRecord{
		PCR: pcr,
		Digests: []celDigest{{
			HashAlg: "sha256",
			Digest:  hex.EncodeToString(digest),
		}},
		Content: celContent{
			EventType: "EV_IPL",
			Data: map[string]string{
				"string": "vanguard-luks-header",
			},
		},
		ContentType: "data",
	}

	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CEL record: %w", err)
	}
	return data, nil
}

// writeCELData writes the RS separator and CEL-JSON data to the given writer.
// Separated from writeEventLogRecord so tests can inject a failing writer
// to exercise the write error paths.
func writeCELData(w io.Writer, data []byte) error {
	if _, err := w.Write([]byte{0x1e}); err != nil {
		return fmt.Errorf("failed to write RS separator: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write CEL record: %w", err)
	}
	return nil
}