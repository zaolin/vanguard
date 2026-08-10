package main

import (
	"encoding/json"
	"testing"
)

func TestParseFwupdSecurityJSON(t *testing.T) {
	raw := `{
		"SecurityAttributes": [
			{
				"AppstreamId": "org.fwupd.hsi.Uefi.SecureBoot",
				"HsiResult": "enabled",
				"HsiLevel": 1,
				"Flags": ["success"]
			},
			{
				"AppstreamId": "org.fwupd.hsi.Amd.PlatformSecureBoot",
				"HsiResult": "not-enabled",
				"HsiLevel": 2,
				"Flags": ["action-contact-oem"]
			},
			{
				"AppstreamId": "org.fwupd.hsi.PlatformDebugLocked",
				"HsiResult": "locked",
				"HsiLevel": 2,
				"Flags": ["success"]
			}
		]
	}`

	var parsed struct {
		SecurityAttributes []struct {
			AppstreamID string   `json:"AppstreamId"`
			HsiResult   string   `json:"HsiResult"`
			HsiLevel    int      `json:"HsiLevel"`
			Flags       []string `json:"Flags"`
		} `json:"SecurityAttributes"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(parsed.SecurityAttributes) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(parsed.SecurityAttributes))
	}

	// First: Secure Boot, success
	a := parsed.SecurityAttributes[0]
	if a.AppstreamID != "org.fwupd.hsi.Uefi.SecureBoot" {
		t.Errorf("attr[0] id: got %s", a.AppstreamID)
	}
	if !containsFlag(a.Flags, "success") {
		t.Error("attr[0] should have success flag")
	}

	// Second: PSB not-enabled, no success
	a = parsed.SecurityAttributes[1]
	if a.HsiResult != "not-enabled" {
		t.Errorf("attr[1] result: got %s", a.HsiResult)
	}
	if containsFlag(a.Flags, "success") {
		t.Error("attr[1] should NOT have success flag")
	}
}

func TestComputeHSILevel_AllPass(t *testing.T) {
	attrs := map[string]fwupdAttr{
		"a": {Success: true, HsiLevel: 1},
		"b": {Success: true, HsiLevel: 1},
		"c": {Success: true, HsiLevel: 2},
		"d": {Success: true, HsiLevel: 2},
		"e": {Success: true, HsiLevel: 3},
	}
	level := computeHSILevel(attrs)
	if level != 3 {
		t.Errorf("all pass → HSI level should be 3, got %d", level)
	}
}

func TestComputeHSILevel_FailAtLevel2(t *testing.T) {
	attrs := map[string]fwupdAttr{
		"a": {Success: true, HsiLevel: 1},
		"b": {Success: true, HsiLevel: 1},
		"c": {Success: false, HsiLevel: 2}, // fails
		"d": {Success: true, HsiLevel: 2},
		"e": {Success: true, HsiLevel: 3},
	}
	level := computeHSILevel(attrs)
	if level != 1 {
		t.Errorf("fail at HSI-2 → level should be 1, got %d", level)
	}
}

func TestComputeHSILevel_Empty(t *testing.T) {
	attrs := map[string]fwupdAttr{}
	level := computeHSILevel(attrs)
	if level != 0 {
		t.Errorf("empty attrs → level should be 0, got %d", level)
	}
}

func TestComputeHSILevel_OnlyRuntime(t *testing.T) {
	// Runtime attributes have HsiLevel=0, should not affect composite
	attrs := map[string]fwupdAttr{
		"a": {Success: true, HsiLevel: 0},
		"b": {Success: false, HsiLevel: 0},
	}
	level := computeHSILevel(attrs)
	if level != 0 {
		t.Errorf("only runtime attrs → level should be 0, got %d", level)
	}
}

func TestFwupdAttrLookup(t *testing.T) {
	f := &fwupdInfo{
		Installed: true,
		Attributes: map[string]fwupdAttr{
			fwupdUefiSecureBoot: {Result: "enabled", Success: true, HsiLevel: 1},
		},
	}

	// Existing attribute
	a := f.attr(fwupdUefiSecureBoot)
	if a == nil {
		t.Fatal("attr should not be nil")
	}
	if a.Result != "enabled" {
		t.Errorf("result: got %s", a.Result)
	}

	// Non-existent attribute
	a = f.attr("org.fwupd.hsi.NonExistent")
	if a != nil {
		t.Error("non-existent attr should return nil")
	}
}

func TestFwupdSuccess(t *testing.T) {
	f := &fwupdInfo{
		Attributes: map[string]fwupdAttr{
			fwupdUefiSecureBoot:        {Success: true},
			fwupdAmdPlatformSecureBoot: {Success: false},
		},
	}

	if !f.success(fwupdUefiSecureBoot) {
		t.Error("Uefi.SecureBoot should be success")
	}
	if f.success(fwupdAmdPlatformSecureBoot) {
		t.Error("Amd.PlatformSecureBoot should NOT be success")
	}
	if f.success("nonexistent") {
		t.Error("nonexistent attr should not be success")
	}
}

func TestFwupdPresent(t *testing.T) {
	f := &fwupdInfo{
		Attributes: map[string]fwupdAttr{
			fwupdUefiSecureBoot: {Success: false}, // present but failed
		},
	}

	if !f.present(fwupdUefiSecureBoot) {
		t.Error("Uefi.SecureBoot should be present even if failed")
	}
	if f.present("nonexistent") {
		t.Error("nonexistent attr should not be present")
	}
}

func TestFwupdResult(t *testing.T) {
	f := &fwupdInfo{
		Attributes: map[string]fwupdAttr{
			fwupdAmdSmmLocked: {Result: "locked"},
		},
	}

	if f.result(fwupdAmdSmmLocked) != "locked" {
		t.Errorf("result: got %s", f.result(fwupdAmdSmmLocked))
	}
	if f.result("nonexistent") != "" {
		t.Error("nonexistent result should be empty string")
	}
}

func TestFwupdNilInfo(t *testing.T) {
	var f *fwupdInfo // nil

	if f.success("anything") {
		t.Error("nil fwupdInfo success should be false")
	}
	if f.present("anything") {
		t.Error("nil fwupdInfo present should be false")
	}
	if f.result("anything") != "" {
		t.Error("nil fwupdInfo result should be empty")
	}
}

func TestFwupdNotInstalled(t *testing.T) {
	f := &fwupdInfo{Installed: false}
	if f.Installed {
		t.Error("should not be installed")
	}
	if f.success(fwupdUefiSecureBoot) {
		t.Error("not installed → success should be false")
	}
}

func TestContainsFlag(t *testing.T) {
	flags := []string{"success", "runtime-issue"}
	if !containsFlag(flags, "success") {
		t.Error("should contain 'success'")
	}
	if containsFlag(flags, "missing") {
		t.Error("should not contain 'missing'")
	}
	if containsFlag(nil, "anything") {
		t.Error("nil flags should return false")
	}
}
