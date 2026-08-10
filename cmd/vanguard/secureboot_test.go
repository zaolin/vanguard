package main

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestIsFactorySubject(t *testing.T) {
	tests := []struct {
		subject string
		want    bool
	}{
		{"C=Platform Key, CN=Platform Key", false},
		{"C=Key Exchange Key, CN=Key Exchange Key", false},
		{"C=Database Key, CN=Database Key", false},
		{"C=US, O=Microsoft Corporation, CN=Microsoft Windows Production PCA 2011", true},
		{"C=US, O=Microsoft Corporation, CN=Microsoft Corporation KEK CA 2011", true},
		{"C=US, O=Microsoft Corporation, CN=Microsoft Corporation UEFI CA 2011", true},
		{"C=US, O=AMI", true},
		{"C=TW, O=ASUS", true},
		{"", false},
		{"C=DE, O=MyCustomCA, CN=My Custom PK", false},
	}

	for _, tt := range tests {
		got := isFactorySubject(tt.subject)
		if got != tt.want {
			t.Errorf("isFactorySubject(%q) = %v, want %v", tt.subject, got, tt.want)
		}
	}
}

func TestIsCustomKeys(t *testing.T) {
	// Empty PK → not custom
	if isCustomKeys(nil, nil, nil) {
		t.Error("empty PK should not be custom")
	}

	// Custom PK (non-factory subject)
	pk := []certInfo{{Subject: "C=Platform Key, CN=Platform Key", IsX509Cert: true}}
	if !isCustomKeys(pk, nil, nil) {
		t.Error("non-factory PK should be custom")
	}

	// Factory PK (Microsoft)
	pkFactory := []certInfo{{Subject: "C=US, O=Microsoft Corporation, CN=Microsoft Root", IsX509Cert: true}}
	if isCustomKeys(pkFactory, nil, nil) {
		t.Error("Microsoft PK should not be custom")
	}

	// Mixed PK (custom + factory) → not all custom → not custom
	pkMixed := []certInfo{
		{Subject: "C=Platform Key, CN=Platform Key", IsX509Cert: true},
		{Subject: "C=US, O=Microsoft, CN=Microsoft KEK", IsX509Cert: true},
	}
	if isCustomKeys(pkMixed, nil, nil) {
		t.Error("mixed PK (custom+factory) should not be all-custom")
	}
}

func TestCountNonCustomCerts(t *testing.T) {
	info := &secureBootInfo{
		PK:  []certInfo{{Subject: "C=Platform Key, CN=Platform Key"}},
		KEK: []certInfo{{Subject: "C=Key Exchange Key, CN=Key Exchange Key"}, {Subject: "C=US, O=Microsoft Corporation, CN=Microsoft KEK"}},
		DB:  []certInfo{{Subject: "C=US, O=Microsoft Corporation, CN=Microsoft Windows Production PCA 2011"}},
	}

	count := countNonCustomCerts(info)
	if count != 2 {
		t.Errorf("countNonCustomCerts = %d, want 2 (1 KEK + 1 db)", count)
	}
}

func TestCheckSecureBootWarnings(t *testing.T) {
	// Setup Mode → critical
	info := &secureBootInfo{SetupMode: true}
	warnings := checkSecureBootWarnings(info)
	if len(warnings) == 0 {
		t.Fatal("expected warnings for Setup Mode")
	}
	if !containsStr(warnings[0], "CRITICAL") {
		t.Errorf("first warning should be CRITICAL, got: %s", warnings[0])
	}

	// Secure Boot disabled (but not Setup Mode) → critical
	info = &secureBootInfo{Enabled: false, SetupMode: false}
	warnings = checkSecureBootWarnings(info)
	found := false
	for _, w := range warnings {
		if containsStr(w, "CRITICAL") {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL warning for disabled Secure Boot")
	}

	// dbx missing → warning
	info = &secureBootInfo{Enabled: true, SetupMode: false, PK: []certInfo{{Subject: "C=PK, CN=PK"}}}
	warnings = checkSecureBootWarnings(info)
	found = false
	for _, w := range warnings {
		if containsStr(w, "WARNING") && containsStr(w, "dbx") {
			found = true
		}
	}
	if !found {
		t.Error("expected WARNING about missing dbx")
	}

	// Expired certificate → warning
	info = &secureBootInfo{
		Enabled:   true,
		SetupMode: false,
		PK:        []certInfo{{Subject: "C=PK, CN=PK", Expired: true, NotAfter: "2020-01-01"}},
		DBX:       []certInfo{{Subject: "SHA256 hash"}},
	}
	warnings = checkSecureBootWarnings(info)
	found = false
	for _, w := range warnings {
		if containsStr(w, "WARNING") && containsStr(w, "expired") {
			found = true
		}
	}
	if !found {
		t.Error("expected WARNING about expired PK certificate")
	}

	// All good → no critical/warning
	info = &secureBootInfo{
		Enabled:    true,
		SetupMode:  false,
		PK:         []certInfo{{Subject: "C=Platform Key, CN=Platform Key"}},
		KEK:        []certInfo{{Subject: "C=Key Exchange Key, CN=Key Exchange Key"}},
		DB:         []certInfo{{Subject: "C=Database Key, CN=Database Key"}},
		DBX:        []certInfo{{Subject: "SHA256 hash"}},
		CustomKeys: true,
	}
	warnings = checkSecureBootWarnings(info)
	for _, w := range warnings {
		if containsStr(w, "CRITICAL") || containsStr(w, "WARNING") {
			t.Errorf("unexpected critical/warning for healthy system: %s", w)
		}
	}
}

func TestPluralY(t *testing.T) {
	if pluralY(1) != "y" {
		t.Error("pluralY(1) should be 'y'")
	}
	if pluralY(0) != "ies" {
		t.Error("pluralY(0) should be 'ies'")
	}
	if pluralY(5) != "ies" {
		t.Error("pluralY(5) should be 'ies'")
	}
}

func TestTruncateSubject(t *testing.T) {
	short := "C=US, O=Test"
	if truncateSubject(short) != short {
		t.Error("short subject should not be truncated")
	}

	long := strings.Repeat("A", 60)
	truncated := truncateSubject(long)
	if len(truncated) != 50 {
		t.Errorf("truncated length = %d, want 50", len(truncated))
	}
	if truncated[47:50] != "..." {
		t.Error("truncated subject should end with '...'")
	}
}

// Test X.509 cert parsing with a real cert
func TestParseX509Cert(t *testing.T) {
	// Test the parsing path with a known-bad DER blob (should fail gracefully)
	_, err := x509.ParseCertificate([]byte{})
	if err == nil {
		t.Error("expected error parsing empty cert")
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
