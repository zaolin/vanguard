package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestSwapExposure pins the swap evaluation: only provably unencrypted swap is
// critical; dm-crypt, zram and no swap are fine.
func TestSwapExposure(t *testing.T) {
	tests := []struct {
		name    string
		entries []swapEntry
		err     error
		want    string
	}{
		{name: "no swap is informational", entries: nil, want: "info"},
		{name: "read failure is informational, not clean", err: os.ErrPermission, want: "info"},
		{name: "plain partition is critical", entries: []swapEntry{{Path: "/dev/sda3", State: swapPlain}}, want: "critical"},
		{name: "plain NVMe partition is critical", entries: []swapEntry{{Path: "/dev/nvme0n1p3", State: swapPlain}}, want: "critical"},
		{name: "dm-crypt is ok", entries: []swapEntry{{Path: "/dev/mapper/gentoo-swap", State: swapEncrypted}}, want: "ok"},
		{name: "unverified encryption is not ok", entries: []swapEntry{{Path: "/dev/mapper/vg/swap", State: swapUnknown}}, want: "info"},
		{name: "zram is not disk exposure", entries: []swapEntry{{Path: "/dev/zram0", State: swapRamBacked}}, want: "info"},
		{name: "one unencrypted area is enough", entries: []swapEntry{{Path: "/dev/mapper/gentoo-swap", State: swapEncrypted}, {Path: "/dev/sda3", State: swapPlain}}, want: "critical"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := swapExposure(tc.entries, tc.err); got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
		})
	}
}

// TestClassifySwap pins the device classification, including that a dm path
// alone is NOT proof of encryption (LVM can be plaintext).
func TestClassifySwap(t *testing.T) {
	orig := dmsetupRunner
	origZram := zramBackingReader
	t.Cleanup(func() {
		dmsetupRunner = orig
		zramBackingReader = origZram
	})
	// No zram backing on the fixture platform.
	zramBackingReader = func(string) string { return "" }
	// The fixtures use pathnames as device references; the resolver seam is
	// what maps major:minor in production.
	origResolver := blockDevResolver
	t.Cleanup(func() { blockDevResolver = origResolver })
	blockDevResolver = func(ref string) string { return ref }
	dmsetupRunner = func(path string) (string, error) {
		if path == "/dev/mapper/plain-lvm" {
			return "0 1000 linear /dev/sda3 0", nil
		}
		if !strings.HasPrefix(path, "/dev/mapper/") && !strings.HasPrefix(path, "/dev/dm-") {
			// dmsetup on a plain block device fails in reality.
			return "", errors.New("not a dm device")
		}
		return "0 1000 crypt aes-xts-plain64 deadbeef", nil
	}

	tests := []struct {
		path string
		want swapState
	}{
		{path: "/dev/sda3", want: swapPlain},
		{path: "/dev/zram0", want: swapRamBacked},
		{path: "/dev/mapper/crypt-lvm", want: swapEncrypted},
		{path: "/dev/mapper/plain-lvm", want: swapPlain},
		{path: "/dev/dm-0", want: swapEncrypted},
	}
	for _, tc := range tests {
		if got := classifySwap(tc.path); got != tc.want {
			t.Errorf("classifySwap(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestClassifySwapDmsetupFailure pins that an unverifiable dm target is
// reported as unknown rather than as encrypted.
func TestClassifySwapDmsetupFailure(t *testing.T) {
	orig := dmsetupRunner
	t.Cleanup(func() { dmsetupRunner = orig })
	dmsetupRunner = func(path string) (string, error) { return "", errors.New("dmsetup not found") }

	if got := classifySwap("/dev/mapper/vg/swap"); got != swapUnknown {
		t.Errorf("state = %v, want unknown for a failed dmsetup call", got)
	}
}

// TestPathWithin pins the mountpoint boundary: /home2 is not inside /home.
func TestPathWithin(t *testing.T) {
	tests := []struct {
		path, mountpoint string
		want             bool
	}{
		{path: "/home/swapfile", mountpoint: "/home", want: true},
		{path: "/home2/swapfile", mountpoint: "/home", want: false},
		{path: "/home2/swapfile", mountpoint: "/", want: true},
		{path: "/home", mountpoint: "/home", want: true},
		{path: "/home2", mountpoint: "/home", want: false},
	}
	for _, tc := range tests {
		if got := pathWithin(tc.path, tc.mountpoint); got != tc.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", tc.path, tc.mountpoint, got, tc.want)
		}
	}
}

// TestMountSourceForPath pins that the longest PROPER ancestor wins, so a swap
// file is attributed to the right mount.
func TestMountSourceForPath(t *testing.T) {
	dir := t.TempDir()
	mounts := dir + "/mounts"
	content := "/dev/mapper/crypt-root / ext4 rw 0 0\n/dev/sda3 /home ext4 rw 0 0\n"
	if err := os.WriteFile(mounts, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	orig := mountsFile
	t.Cleanup(func() { mountsFile = orig })
	mountsFile = mounts

	if got := mountSourceForPath("/home2/swapfile"); got != "/dev/mapper/crypt-root" {
		t.Errorf("source = %q, want /dev/mapper/crypt-root (not /home)", got)
	}
	if got := mountSourceForPath("/home/swapfile"); got != "/dev/sda3" {
		t.Errorf("source = %q, want /dev/sda3", got)
	}
}

// TestSuspendExposure pins the S3 evaluation, including the read-failure case.
func TestSuspendExposure(t *testing.T) {
	tests := []struct {
		name     string
		memSleep string
		readErr  error
		enc      bool
		want     string
	}{
		{name: "S3 without encryption is a warning", memSleep: "[s2idle] deep", enc: false, want: "warning"},
		{name: "S3 with encryption is ok", memSleep: "[s2idle] deep", enc: true, want: "ok"},
		{name: "no S3 is informational", memSleep: "[s2idle]", enc: false, want: "info"},
		{name: "read failure is informational", readErr: os.ErrPermission, memSleep: "[s2idle] deep", want: "info"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := suspendExposure("freeze mem standby disk", tc.memSleep, tc.readErr, tc.enc); got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
		})
	}
}

// TestPcrsAllZero pins the all-zero detection and that no data is not a
// finding.
func TestPcrsAllZero(t *testing.T) {
	zeros := "0000000000000000000000000000000000000000000000000000000000000000"

	if !pcrsAllZero([]pcrStatus{{Current: zeros}, {Current: zeros}}) {
		t.Error("all-zero PCRs were not detected")
	}
	if pcrsAllZero([]pcrStatus{{Current: zeros}, {Current: "0000000000000000000000000000000000000000000000000000000000000001"}}) {
		t.Error("a non-zero PCR was reported as all-zero")
	}
	if pcrsAllZero(nil) {
		t.Error("no data was reported as all-zero (should be unknown)")
	}
	if pcrsAllZero([]pcrStatus{{Current: ""}}) {
		t.Error("an unreadable PCR was reported as all-zero (should be unknown)")
	}
}

// TestHealthVectorAllZeroPCRs pins that the mitigation is actually emitted in
// the health vector, not just evaluated by the helper.
func TestHealthVectorAllZeroPCRs(t *testing.T) {
	zeros := "0000000000000000000000000000000000000000000000000000000000000000"
	data := &statusData{}
	data.TPM.Present = true
	data.TPM.Banks = []string{"sha256"}
	data.PCRLock = &pcrlockInfo{
		PolicyPath: "/boot/policy.json",
		PCRResults: []pcrStatus{{PCR: 0, IsEnforced: true, Current: zeros}},
	}

	v := buildTPMHealthVector(data)

	found := false
	for _, m := range v.Mitigations {
		if m.Name == "PCR measurements" {
			found = true
			if m.Status != "warning" {
				t.Errorf("PCR measurements status = %q, want warning", m.Status)
			}
		}
	}
	if !found {
		t.Error("no PCR measurements mitigation in the health vector")
	}
}

// TestComputeTierIgnoresAdvisories pins that vendor advisories do not drag the
// protection tier down, while a verified warning still does.
func TestComputeTierIgnoresAdvisories(t *testing.T) {
	data := &statusData{}
	data.LUKSDevices = []luksDeviceInfo{{Token: &tokenDetail{}}}
	data.ThreatModel = []threatVector{{
		Name: "TPM Vulnerabilities (vendor/firmware)",
		Mitigations: []mitigation{
			{Name: "faulTPM", Status: "advisory"},
			{Name: "TPM-Fail", Status: "advisory"},
		},
	}}
	for i := range data.ThreatModel {
		data.ThreatModel[i].Status = vectorStatus(&data.ThreatModel[i])
		data.ThreatModel[i].Collapsed = vectorIsCollapsed(&data.ThreatModel[i])
	}

	computeTier(data)
	if data.Tier == "WARNING" || data.Tier == "CRITICAL" {
		t.Errorf("an advisory degraded the tier to %s", data.Tier)
	}

	// A verified warning must still count.
	data.ThreatModel[0].Mitigations = append(data.ThreatModel[0].Mitigations, mitigation{
		Name: "Seal/unseal roundtrip", Status: "warning",
	})
	data.ThreatModel[0].Status = vectorStatus(&data.ThreatModel[0])
	computeTier(data)
	if data.Tier != "WARNING" {
		t.Errorf("a verified warning did not degrade the tier: %s", data.Tier)
	}
}

// TestAdvisoryDoesNotExpandVector pins that an advisory-only vector collapses
// like an informational one instead of being presented as a problem.
func TestAdvisoryDoesNotExpandVector(t *testing.T) {
	v := threatVector{Mitigations: []mitigation{{Status: "advisory"}}}
	if !vectorIsCollapsed(&v) {
		t.Error("an advisory-only vector should collapse")
	}
}

// TestSwapExposureOrdering pins that a zram or unverified entry never hides a
// plaintext swap behind it: all areas are evaluated before deciding.
func TestSwapExposureOrdering(t *testing.T) {
	entries := []swapEntry{
		{Path: "/dev/zram0", State: swapRamBacked},
		{Path: "/dev/mapper/vg/other", State: swapUnknown},
		{Path: "/dev/sda3", State: swapPlain},
	}
	if got := swapExposure(entries, nil); got.Status != "critical" {
		t.Errorf("status = %q, want critical for plaintext swap behind zram/unverified", got.Status)
	}
}

// TestZramBackingDevice pins that zram WITH a backing device is judged by that
// device, not by the zram name alone.
func TestZramBackingDevice(t *testing.T) {
	orig := zramBackingReader
	t.Cleanup(func() { zramBackingReader = orig })

	origDm2 := dmsetupRunner
	t.Cleanup(func() { dmsetupRunner = origDm2 })
	dmsetupRunner = func(path string) (string, error) { return "", errors.New("no dm") }
	zramBackingReader = func(path string) string { return "/dev/sda3" }
	if got := classifySwap("/dev/zram0"); got != swapPlain {
		t.Errorf("zram with a plain backing partition = %v, want swapPlain", got)
	}

	zramBackingReader = func(path string) string { return "/dev/mapper/crypt-lvm" }
	origDm := dmsetupRunner
	t.Cleanup(func() { dmsetupRunner = origDm })
	dmsetupRunner = func(path string) (string, error) { return "0 1000 crypt aes-xts-plain64 deadbeef", nil }
	if got := classifySwap("/dev/zram0"); got != swapEncrypted {
		t.Errorf("zram with a dm-crypt backing = %v, want swapEncrypted", got)
	}

	zramBackingReader = func(path string) string { return "" }
	if got := classifySwap("/dev/zram0"); got != swapRamBacked {
		t.Errorf("zram without a backing device = %v, want swapRamBacked", got)
	}
}

// TestDmTargetStateMixedTable pins the evaluation with REAL dmsetup output:
// backing devices are reported as major:minor and must be resolved.
func TestDmTargetStateMixedTable(t *testing.T) {
	orig := dmsetupRunner
	origResolver := blockDevResolver
	t.Cleanup(func() {
		dmsetupRunner = orig
		blockDevResolver = origResolver
	})

	// major:minor → device path mapping (what /dev/block provides).
	blockDevResolver = func(ref string) string {
		switch ref {
		case "254:0":
			return "/dev/mapper/crypt-pv"
		case "8:3":
			return "/dev/sda3"
		default:
			return ""
		}
	}
	dmsetupRunner = func(path string) (string, error) {
		switch path {
		case "/dev/mapper/mixed":
			return "0 1000 crypt aes-xts-plain64 deadbeef\n1000 500 linear 8:3 0", nil
		case "/dev/mapper/crypt-pv":
			return "0 1000 crypt aes-xts-plain64 deadbeef", nil
		case "/dev/mapper/vg-swap":
			return "0 1000 linear 254:0 0", nil
		case "/dev/mapper/raid-swap":
			return "0 1000 raid raid1 2 8:3 8:19", nil
		default:
			return "", errors.New("unknown device")
		}
	}

	// A mixed table: one crypt segment, one linear segment on a plain PV.
	if got := dmTargetState("/dev/mapper/mixed"); got != swapPlain {
		t.Errorf("mixed linear+crypt table = %v, want swapPlain", got)
	}

	// The standard LVM-over-LUKS layout: a linear segment on a dm-crypt PV.
	if got := dmTargetState("/dev/mapper/vg-swap"); got != swapEncrypted {
		t.Errorf("LVM on a dm-crypt PV = %v, want swapEncrypted", got)
	}

	// RAID targets are not provably encrypted: unknown, not a false verdict.
	if got := dmTargetState("/dev/mapper/raid-swap"); got != swapUnknown {
		t.Errorf("RAID target = %v, want swapUnknown", got)
	}
}

// TestZramBackingReadError pins that a failed backing_dev read is unknown, not
// "no disk exposure".
func TestZramBackingReadError(t *testing.T) {
	orig := zramBackingReader
	t.Cleanup(func() { zramBackingReader = orig })
	zramBackingReader = func(path string) string { return "unknown" }

	if got := classifySwap("/dev/zram0"); got != swapUnknown {
		t.Errorf("zram with an unreadable backing device = %v, want swapUnknown", got)
	}
}

// TestZramBackingReaderParsing exercises the PRODUCTION sysfs parsing: the
// kernel reports "none" for RAM-only zram, a full path when writeback is
// configured, and a bare device name otherwise.
func TestZramBackingReaderParsing(t *testing.T) {
	dir := t.TempDir()
	orig := sysBlockRoot
	t.Cleanup(func() { sysBlockRoot = orig })
	sysBlockRoot = dir

	write := func(content string) {
		t.Helper()
		if err := os.MkdirAll(dir+"/zram0", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir+"/zram0/backing_dev", []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	write("none\n")
	if got := zramBackingReader("/dev/zram0"); got != "" {
		t.Errorf("backing_dev 'none' = %q, want empty (RAM-only)", got)
	}

	write("/dev/mapper/crypt-pv\n")
	if got := zramBackingReader("/dev/zram0"); got != "/dev/mapper/crypt-pv" {
		t.Errorf("a full path was mangled: %q", got)
	}

	write("sda3\n")
	if got := zramBackingReader("/dev/zram0"); got != "/dev/sda3" {
		t.Errorf("a bare device name = %q, want /dev/sda3", got)
	}

	if err := os.Remove(dir + "/zram0/backing_dev"); err != nil {
		t.Fatal(err)
	}
	if got := zramBackingReader("/dev/zram0"); got != "" {
		t.Errorf("a missing backing_dev file = %q, want empty", got)
	}
}

// TestNestedUnknownIsNotPlain pins that an unresolvable or RAID-backed PV is
// reported as unknown, not as provably plaintext.
func TestNestedUnknownIsNotPlain(t *testing.T) {
	orig := dmsetupRunner
	origResolver := blockDevResolver
	t.Cleanup(func() {
		dmsetupRunner = orig
		blockDevResolver = origResolver
	})

	blockDevResolver = func(ref string) string { return "/dev/mapper/raid-pv" }
	dmsetupRunner = func(path string) (string, error) {
		if path == "/dev/mapper/vg-swap" {
			return "0 1000 linear 254:9 0", nil
		}
		// The nested PV is a RAID target: not provably encrypted.
		return "0 1000 raid raid1 2 8:3 8:19", nil
	}

	if got := dmTargetState("/dev/mapper/vg-swap"); got != swapUnknown {
		t.Errorf("a nested RAID PV = %v, want swapUnknown (not swapPlain)", got)
	}
}

// TestMemoryEncryptionActiveNowRequiresEvidence pins that a CPU capability
// flag alone is not enough for the suspend check: only kernel evidence counts.
func TestMemoryEncryptionActiveNowRequiresEvidence(t *testing.T) {
	origRunner := dmesgRunner
	origReader := kmsgReader
	origTSME := detectTSMEFn
	t.Cleanup(func() {
		dmesgRunner = origRunner
		kmsgReader = origReader
		detectTSMEFn = origTSME
	})
	// No TSME on the fixture platform: the kernel evidence decides.
	detectTSMEFn = func() (bool, int) { return false, 0 }
	dmesgRunner = func() ([]byte, error) { return []byte("x86/tme: not enabled by BIOS\n"), nil }
	kmsgReader = func() (string, error) { return "", os.ErrNotExist }

	if memoryEncryptionActiveNow() {
		t.Error("TME-not-enabled-by-BIOS was reported as active")
	}

	dmesgRunner = func() ([]byte, error) { return []byte("x86/tme: enabled by BIOS\n"), nil }
	if !memoryEncryptionActiveNow() {
		t.Error("TME enabled by BIOS was not reported as active")
	}

	// AMD: the kernel prints this only when the features are actually active.
	dmesgRunner = func() ([]byte, error) { return []byte("Memory Encryption Features active: AMD SME\n"), nil }
	if !memoryEncryptionActiveNow() {
		t.Error("an active AMD memory-encryption message was not recognized")
	}
}
