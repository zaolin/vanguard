package main

import (
	"strings"
	"testing"
)

// TestUnknownPCRIsNotAMismatch pins that an unreadable PCR is reported as
// unknown, not as a security mismatch.
func TestUnknownPCRIsNotAMismatch(t *testing.T) {
	data := &statusData{}
	data.PCRLock = &pcrlockInfo{
		PolicyPath:    "/boot/policy.json",
		PolicyNVIndex: 0x01919ea9,
		PCRResults: []pcrStatus{
			{PCR: 7, Name: "secure-boot", IsEnforced: true, Unknown: true},
		},
	}

	v := buildBootChainTamperingVector(data)

	for _, m := range v.Mitigations {
		if strings.Contains(m.Detail, "MISMATCH") {
			t.Errorf("an unknown PCR was reported as a mismatch: %+v", m)
		}
		if m.Status == "critical" && m.Name == "PCRLock PCR binding" {
			t.Errorf("an unknown PCR produced a critical finding: %+v", m)
		}
	}
}

// TestNVUnknownIsNotCritical pins that an unreadable NV state is reported as
// unverifiable rather than as a critical "NOT on TPM".
func TestNVUnknownIsNotCritical(t *testing.T) {
	data := &statusData{}
	data.PCRLock = &pcrlockInfo{
		PolicyPath:     "/boot/policy.json",
		PolicyNVIndex:  0x01919ea9,
		NVIndex:        0x01919ea9,
		NVOnTPMUnknown: true,
	}

	v := buildBootChainTamperingVector(data)

	found := false
	for _, m := range v.Mitigations {
		if m.Name == "PCRLock NV index" {
			found = true
			if m.Status != "info" {
				t.Errorf("NV status = %q, want info for an unreadable state", m.Status)
			}
		}
		if strings.Contains(m.Detail, "NOT on TPM") {
			t.Errorf("an unreadable NV state was reported as missing: %+v", m)
		}
	}
	if !found {
		t.Error("no NV mitigation")
	}
}

// TestAuditTesthotpGating pins the initrd's activation rule: testhotp only
// takes effect together with test mode.
func TestAuditTesthotpGating(t *testing.T) {
	alone := auditKernelCmdline("vanguard.testhotp=1")
	if len(alone) != 1 || alone[0].Status != "info" {
		t.Errorf("testhotp alone should be inert (info), got %v", alone)
	}

	both := auditKernelCmdline("vanguard.testmode=1 vanguard.testhotp=1")
	if len(both) != 2 {
		t.Fatalf("expected two findings with test mode and testhotp, got %v", both)
	}
	for _, m := range both {
		if m.Status != "critical" {
			t.Errorf("%s should be critical with test mode active, got %q", m.Name, m.Status)
		}
	}
}

// TestAuditTestpinEmptyValue pins that a bare or empty testpin parameter is
// not a finding: getTestPin requires a value.
func TestAuditTestpinEmptyValue(t *testing.T) {
	for _, cmdline := range []string{"vanguard.testpin", "vanguard.testpin="} {
		if got := auditKernelCmdline(cmdline); len(got) != 0 {
			t.Errorf("cmdline %q produced %v, want no findings", cmdline, got)
		}
	}
}

// TestAuditTestmodeSubstringVariants pins that the audit matches the initrd's
// substring semantics for test mode.
func TestAuditTestmodeSubstringVariants(t *testing.T) {
	for _, cmdline := range []string{"vanguard.testmode=10", "x=vanguard.testmode=1"} {
		got := auditKernelCmdline(cmdline)
		if len(got) != 1 || got[0].Status != "critical" {
			t.Errorf("cmdline %q should be critical like the initrd, got %v", cmdline, got)
		}
	}
}
