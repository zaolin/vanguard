package pcrlock

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// HeaderBindingResult captures the state of the LUKS header PCR 11 binding.
//
// Background: the pcrlock policy's PCR 11 value is an at-unseal-time
// prediction (sd-stub kernel measurement + LUKS header hash, computed with
// --location=756). After the disk is unlocked, systemd extends PCR 11
// further (850-sysinit, 900-ready phases), so the live PCR 11 value in a
// booted system legitimately diverges from the policy prediction. Comparing
// the live PCR 11 against the policy therefore always mismatches and is not
// a security signal.
//
// The property that actually matters — the on-disk LUKS header is unchanged
// since enrollment — is directly checkable by comparing the on-disk header
// digest against the enrollment-time component files:
//
//	/etc/pcrlock.d/755-vanguard-luks-header.pcrlock.d/luks-header.pcrlock        (next-boot hash, written at enrollment)
//	/etc/pcrlock.d/755-vanguard-luks-header.pcrlock.d/luks-header-eventlog.pcrlock (previous-boot hash, written at enrollment)
type HeaderBindingResult struct {
	// Bound is true when a real (non-masked) LUKS header component exists.
	Bound bool
	// Match is true when the on-disk header digest equals one of the
	// enrollment-time digests. Meaningful only when Bound is true.
	Match bool
	// Detail is a human-readable explanation of the result.
	Detail string
	// OnDiskDigest is the current on-disk LUKS2 header digest (hex), empty
	// when the header could not be read.
	OnDiskDigest string
	// EnrolledDigests are the digests captured at enrollment time (hex).
	EnrolledDigests []string
}

// luksHeaderVariantDirName is the pcrlock component directory holding the
// enrollment-time LUKS header digests.
const luksHeaderVariantDirName = "755-vanguard-luks-header.pcrlock.d"

// PCRUsedForLUKSHeaderBinding is the PCR index the LUKS header hash is
// extended into (mirrors init/luks/measure.go).
const PCRUsedForLUKSHeaderBinding = 11

// VerifyLUKSHeaderBinding checks whether the on-disk LUKS2 header of
// devicePath still matches the digest(s) captured at enrollment time.
//
// It does NOT read the TPM and does NOT depend on the boot phase, so it
// returns the same answer on a live system and after boot.
//
// A missing variant directory or a /dev/null mask means PCR 11 header
// binding is not enrolled (Bound=false, Match=false) — callers should treat
// that as "not bound", not as a mismatch.
func VerifyLUKSHeaderBinding(devicePath string) (*HeaderBindingResult, error) {
	res := &HeaderBindingResult{}

	variantDir := filepath.Join(PCRLockDir, luksHeaderVariantDirName)

	// Detect masking: MaskPolicy symlinks 755-vanguard-luks-header.pcrlock
	// (the component name without .d) to /dev/null.
	maskPath := filepath.Join(PCRLockDir, luksHeaderVariantDirName[:len(luksHeaderVariantDirName)-2])
	if fi, err := os.Lstat(maskPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(maskPath); err == nil && target == "/dev/null" {
			res.Detail = "not bound — LUKS header binding masked (--no-luks-header)"
			return res, nil
		}
	}

	// Collect enrollment-time digests from every *.pcrlock variant in the
	// component directory. Masked variants inside the directory are skipped.
	entries, err := os.ReadDir(variantDir)
	if err != nil {
		if os.IsNotExist(err) {
			res.Detail = "not bound — no LUKS header component (use -l <luks-dev> with vanguard update)"
			return res, nil
		}
		return nil, fmt.Errorf("failed to read LUKS header component directory: %w", err)
	}

	var enrolled [][]byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".pcrlock" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(variantDir, entry.Name()))
		if err != nil {
			continue
		}
		digests, err := parseHeaderComponentDigests(data)
		if err != nil {
			continue
		}
		enrolled = append(enrolled, digests...)
	}

	if len(enrolled) == 0 {
		res.Detail = "not bound — LUKS header component empty or unreadable"
		return res, nil
	}

	for _, d := range enrolled {
		res.EnrolledDigests = append(res.EnrolledDigests, hex.EncodeToString(d))
	}

	// Compute the current on-disk header digest.
	onDisk, err := computeLUKSHeaderDigest(devicePath)
	if err != nil {
		return res, fmt.Errorf("failed to hash LUKS2 header: %w", err)
	}
	res.OnDiskDigest = hex.EncodeToString(onDisk)

	res.Bound = true
	for _, d := range enrolled {
		if bytesEqualPcrlock(onDisk, d) {
			res.Match = true
			break
		}
	}

	if res.Match {
		res.Detail = "LUKS header unchanged since enrollment"
	} else {
		res.Detail = "LUKS header changed since enrollment"
	}

	return res, nil
}

// bytesEqualPcrlock compares two byte slices for equality.
func bytesEqualPcrlock(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseHeaderComponentDigests extracts all sha256 PCR 11 digests from a
// systemd-pcrlock component file (the .pcrlock JSON format written by
// LockLUKSHeader):
//
//	{"records": [{"pcr": 11, "digests": [{"hashAlg": "sha256", "digest": "..."}]}]}
func parseHeaderComponentDigests(data []byte) ([][]byte, error) {
	var file struct {
		Records []struct {
			PCR     int `json:"pcr"`
			Digests []struct {
				HashAlg string `json:"hashAlg"`
				Digest  string `json:"digest"`
			} `json:"digests"`
		} `json:"records"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}

	var out [][]byte
	for _, rec := range file.Records {
		if rec.PCR != PCRUsedForLUKSHeaderBinding {
			continue
		}
		for _, d := range rec.Digests {
			if d.HashAlg != "sha256" {
				continue
			}
			raw, err := hex.DecodeString(d.Digest)
			if err != nil || len(raw) != 32 {
				continue
			}
			out = append(out, raw)
		}
	}
	return out, nil
}
