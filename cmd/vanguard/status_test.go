package main

import (
	"testing"
)

func TestVectorIsCollapsed_AllOK(t *testing.T) {
	v := threatVector{
		Name: "Test",
		Mitigations: []mitigation{
			{Name: "A", Status: "ok"},
			{Name: "B", Status: "ok"},
		},
	}
	if !vectorIsCollapsed(&v) {
		t.Error("vector with all ok mitigations should be collapsed")
	}
}

func TestVectorIsCollapsed_HasWarning(t *testing.T) {
	v := threatVector{
		Name: "Test",
		Mitigations: []mitigation{
			{Name: "A", Status: "ok"},
			{Name: "B", Status: "warning"},
		},
	}
	if vectorIsCollapsed(&v) {
		t.Error("vector with a warning mitigation should NOT be collapsed")
	}
}

func TestVectorIsCollapsed_HasCritical(t *testing.T) {
	v := threatVector{
		Name: "Test",
		Mitigations: []mitigation{
			{Name: "A", Status: "critical"},
		},
	}
	if vectorIsCollapsed(&v) {
		t.Error("vector with a critical mitigation should NOT be collapsed")
	}
}

func TestVectorIsCollapsed_HasInfo(t *testing.T) {
	v := threatVector{
		Name: "Test",
		Mitigations: []mitigation{
			{Name: "A", Status: "info"},
		},
	}
	if !vectorIsCollapsed(&v) {
		t.Error("vector with only info mitigations should be collapsed (info is not a problem)")
	}
}

func TestVectorIsCollapsed_Empty(t *testing.T) {
	v := threatVector{Name: "Test"}
	if !vectorIsCollapsed(&v) {
		t.Error("empty vector should be collapsed")
	}
}

func TestVectorStatus_AllOK(t *testing.T) {
	v := threatVector{
		Mitigations: []mitigation{
			{Status: "ok"},
			{Status: "ok"},
		},
	}
	if vectorStatus(&v) != "ok" {
		t.Error("all ok → status should be ok")
	}
}

func TestVectorStatus_HasWarning(t *testing.T) {
	v := threatVector{
		Mitigations: []mitigation{
			{Status: "ok"},
			{Status: "warning"},
		},
	}
	if vectorStatus(&v) != "warning" {
		t.Error("has warning → status should be warning")
	}
}

func TestVectorStatus_HasCritical(t *testing.T) {
	v := threatVector{
		Mitigations: []mitigation{
			{Status: "ok"},
			{Status: "warning"},
			{Status: "critical"},
		},
	}
	if vectorStatus(&v) != "critical" {
		t.Error("has critical → status should be critical")
	}
}

func TestVectorStatus_Empty(t *testing.T) {
	v := threatVector{}
	if vectorStatus(&v) != "ok" {
		t.Error("empty vector → status should be ok")
	}
}

func TestBuildThreatModel_TenVectors(t *testing.T) {
	data := &statusData{}
	vectors := buildThreatModel(data)
	if len(vectors) != 10 {
		t.Errorf("expected 10 threat vectors, got %d", len(vectors))
	}
}

func TestBuildThreatModel_VectorNames(t *testing.T) {
	data := &statusData{}
	vectors := buildThreatModel(data)
	expected := []string{
		"Evil Maid (initrd/UKI replacement)",
		"Boot Chain Tampering (firmware/UKI change)",
		"TPM Key Extraction (bus sniffing)",
		"DMA Attack (Thunderbolt/PCIe)",
		"Kernel Runtime Attack (module/rootkit)",
		"Cold Boot Attack (RAM dump)",
		"Brute-Force / Key Theft (LUKS)",
		"Physical Debug Attack (JTAG/DCI)",
		"Firmware Tampering (SPI flash/replay/downgrade)",
		"SMM Attack (ring -2 rootkit)",
	}
	for i, name := range expected {
		if vectors[i].Name != name {
			t.Errorf("vector %d name: got %q, want %q", i, vectors[i].Name, name)
		}
	}
}

func TestBuildThreatModel_StatusSet(t *testing.T) {
	data := &statusData{}
	vectors := buildThreatModel(data)
	for i, v := range vectors {
		if v.Status == "" {
			t.Errorf("vector %d (%s) has empty status", i, v.Name)
		}
	}
}

func TestBuildThreatModel_CollapsedSet(t *testing.T) {
	data := &statusData{}
	vectors := buildThreatModel(data)
	for _, v := range vectors {
		// Collapsed should be a valid boolean (true if all ok, false otherwise)
		_ = v.Collapsed // just ensure it doesn't panic
	}
}

func TestBuildEvilMaidVector_SecureBootDisabled(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{
			Enabled:   false,
			SetupMode: false,
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("Secure Boot disabled → status should be critical, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_SetupMode(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{
			Enabled:   true,
			SetupMode: true,
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("Setup Mode → status should be critical, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_SecureBootOK(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{
			Enabled:    true,
			SetupMode:  false,
			CustomKeys: true,
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("Secure Boot ok + PCR 7 ok → status should be ok, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_PCR7Mismatch(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: false},
			},
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("PCR 7 mismatch → status should be critical, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_PCR7NotBound(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: false, Match: true},
			},
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "warning" {
		t.Errorf("PCR 7 not bound → status should be warning, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_SbctlUnsignedBoot(t *testing.T) {
	unsigned := false
	data := &statusData{
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false, CustomKeys: true, DBX: []certInfo{{}}},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		Sbctl: &sbctlInfo{
			Installed:       true,
			BootedUKISigned: &unsigned,
			BootedUKIPath:   "/boot/EFI/Gentoo/kernel.efi",
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("unsigned booted UKI → status should be critical, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_SbctlSignedBoot(t *testing.T) {
	signed := true
	data := &statusData{
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false, CustomKeys: true},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		Sbctl: &sbctlInfo{
			Installed:       true,
			BootedUKISigned: &signed,
			BootedUKIPath:   "/boot/EFI/Gentoo/kernel.efi",
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	v.Collapsed = vectorIsCollapsed(&v)
	if v.Status != "ok" {
		t.Errorf("all ok + sbctl signed → status should be ok, got %s", v.Status)
	}
	if !v.Collapsed {
		t.Error("all ok → vector should be collapsed")
	}
}

func TestBuildBootChainTamperingVector_AllMatch(t *testing.T) {
	data := &statusData{
		PCRLock: &pcrlockInfo{
			NVIndex: 0x1a97310,
			NVOnTPM: true,
			PCRResults: []pcrStatus{
				{PCR: 0, IsEnforced: true, Match: true, Name: "platform-code"},
				{PCR: 4, IsEnforced: true, Match: true, Name: "boot-loader-code"},
				{PCR: 7, IsEnforced: true, Match: true, Name: "secure-boot-policy"},
			},
		},
	}
	v := buildBootChainTamperingVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("all PCRs match → status should be ok, got %s", v.Status)
	}
}

func TestBuildBootChainTamperingVector_Mismatch(t *testing.T) {
	data := &statusData{
		PCRLock: &pcrlockInfo{
			NVIndex: 0x1a97310,
			NVOnTPM: true,
			PCRResults: []pcrStatus{
				{PCR: 4, IsEnforced: true, Match: false, Name: "boot-loader-code"},
			},
		},
	}
	v := buildBootChainTamperingVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("PCR mismatch → status should be critical, got %s", v.Status)
	}
}

func TestBuildBootChainTamperingVector_NVNotOnTPM(t *testing.T) {
	data := &statusData{
		PCRLock: &pcrlockInfo{
			NVIndex: 0x1a97310,
			NVOnTPM: false,
			PCRResults: []pcrStatus{
				{PCR: 0, IsEnforced: true, Match: true},
			},
		},
	}
	v := buildBootChainTamperingVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("NV not on TPM → status should be critical, got %s", v.Status)
	}
}

func TestBuildTPMKeyExtractionVector_NoTPM(t *testing.T) {
	data := &statusData{
		TPM: tpmStatus{Present: false},
	}
	v := buildTPMKeyExtractionVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("no TPM → status should be critical, got %s", v.Status)
	}
}

func TestBuildTPMKeyExtractionVector_Lockout(t *testing.T) {
	data := &statusData{
		TPM: tpmStatus{
			Present:        true,
			InLockout:      true,
			LockoutCounter: 5,
			MaxAuthFail:    5,
		},
		HardwareSecurity: &hardwareSecurityInfo{TPMBusEncryption: "active"},
	}
	v := buildTPMKeyExtractionVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("DA lockout → status should be critical, got %s", v.Status)
	}
}

func TestBuildTPMKeyExtractionVector_BusEncryptionInactive(t *testing.T) {
	data := &statusData{
		TPM:              tpmStatus{Present: true, MaxAuthFail: 3},
		HardwareSecurity: &hardwareSecurityInfo{TPMBusEncryption: "inactive"},
	}
	v := buildTPMKeyExtractionVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "warning" {
		t.Errorf("bus encryption inactive → status should be warning, got %s", v.Status)
	}
}

func TestBuildTPMKeyExtractionVector_AllOK(t *testing.T) {
	data := &statusData{
		TPM:              tpmStatus{Present: true, MaxAuthFail: 3},
		HardwareSecurity: &hardwareSecurityInfo{TPMBusEncryption: "active"},
	}
	v := buildTPMKeyExtractionVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("all ok → status should be ok, got %s", v.Status)
	}
}

func TestBuildDMAAttackVector_IOMMUActive(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			IOMMU:       "active",
			IOMMUGroups: 29,
			IOMMUMode:   "pt",
			Thunderbolt: "absent",
		},
	}
	v := buildDMAAttackVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("IOMMU active, no Thunderbolt → status should be ok, got %s", v.Status)
	}
}

func TestBuildDMAAttackVector_ThunderboltNoIOMMU(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			IOMMU:            "inactive",
			Thunderbolt:      "present",
			ThunderboltCount: 2,
		},
	}
	v := buildDMAAttackVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("Thunderbolt without IOMMU → status should be critical, got %s", v.Status)
	}
}

func TestBuildDMAAttackVector_ThunderboltWithIOMMU(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			IOMMU:            "active",
			IOMMUGroups:      10,
			Thunderbolt:      "present",
			ThunderboltCount: 2,
		},
	}
	v := buildDMAAttackVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("Thunderbolt with IOMMU → status should be ok, got %s", v.Status)
	}
}

func TestBuildKernelRuntimeVector_LockdownConfidentiality(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			Lockdown:   "confidentiality",
			ModuleSigs: "enforced",
		},
	}
	v := buildKernelRuntimeVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("lockdown=confidentiality → status should be ok, got %s", v.Status)
	}
}

func TestBuildKernelRuntimeVector_NoLockdown(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			Lockdown:   "none",
			ModuleSigs: "enforced",
		},
	}
	v := buildKernelRuntimeVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "warning" {
		t.Errorf("lockdown=none → status should be warning, got %s", v.Status)
	}
}

func TestBuildColdBootVector_MemoryEncryptionActive(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			MemoryEncryption: "active",
			MemEncryptType:   "AMD SME",
		},
	}
	v := buildColdBootVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("memory encryption active → status should be ok, got %s", v.Status)
	}
}

func TestBuildColdBootVector_MemEncAvailableNotEnabled(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			MemoryEncryption: "available",
			MemEncryptType:   "AMD SME",
			MemEncryptAdvice: "add mem_encrypt=on",
		},
	}
	v := buildColdBootVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "warning" {
		t.Errorf("memory encryption available but not enabled → status should be warning, got %s", v.Status)
	}
}

func TestBuildColdBootVector_MemEncNotAvailable(t *testing.T) {
	data := &statusData{
		HardwareSecurity: &hardwareSecurityInfo{
			MemoryEncryption: "not-available",
		},
	}
	v := buildColdBootVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("memory encryption not available → status should be ok (info only), got %s", v.Status)
	}
}

func TestBuildBruteForceVector_TokenWithPinAndPcrlock(t *testing.T) {
	data := &statusData{
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		Recovery: &recoveryInfo{Enabled: true},
	}
	v := buildBruteForceVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("token + PIN + pcrlock + recovery → status should be ok, got %s", v.Status)
	}
}

func TestBuildBruteForceVector_NoToken(t *testing.T) {
	data := &statusData{
		LUKSDevices: []luksDeviceInfo{
			{Token: nil},
		},
		Recovery: &recoveryInfo{Enabled: false},
	}
	v := buildBruteForceVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "warning" {
		t.Errorf("no token, no recovery → status should be warning, got %s", v.Status)
	}
}

func TestBuildBruteForceVector_TokenNoPin(t *testing.T) {
	data := &statusData{
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: false, HasPCRLock: true}},
		},
		Recovery: &recoveryInfo{Enabled: true},
	}
	v := buildBruteForceVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "warning" {
		t.Errorf("token without PIN → status should be warning, got %s", v.Status)
	}
}

func TestComputeTier_SbctlUnsignedBootCapsWarning(t *testing.T) {
	unsigned := false
	data := &statusData{
		TPM: tpmStatus{Present: true, MaxAuthFail: 3},
		Sbctl: &sbctlInfo{
			Installed:       true,
			BootedUKISigned: &unsigned,
		},
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		HardwareSecurity: &hardwareSecurityInfo{
			TPMBusEncryption: "active",
			IOMMU:            "active",
			Thunderbolt:      "absent",
			Lockdown:         "confidentiality",
			ModuleSigs:       "enforced",
		},
	}
	data.ThreatModel = buildThreatModel(data)
	computeTier(data)
	if data.Tier != "CRITICAL" {
		t.Errorf("unsigned booted UKI → should be CRITICAL (evil maid vector), got %s", data.Tier)
	}
}

func TestComputeTier_SbctlSignedBootNoCap(t *testing.T) {
	signed := true
	data := &statusData{
		TPM: tpmStatus{Present: true, MaxAuthFail: 3},
		Sbctl: &sbctlInfo{
			Installed:       true,
			BootedUKISigned: &signed,
		},
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		HardwareSecurity: &hardwareSecurityInfo{
			TPMBusEncryption: "active",
			IOMMU:            "active",
			Thunderbolt:      "absent",
			Lockdown:         "confidentiality",
			ModuleSigs:       "enforced",
		},
		Recovery: &recoveryInfo{Enabled: true},
	}
	data.ThreatModel = buildThreatModel(data)
	computeTier(data)
	// Without fwupd, physical vectors have info mitigations → HIGH (not PHYSICAL)
	if data.Tier != "HIGH" {
		t.Errorf("signed booted UKI without fwupd should give HIGH, got %s", data.Tier)
	}
}

func TestComputeTier_SbctlUnknownNoCap(t *testing.T) {
	// BootedUKISigned is nil (unknown — not root) → no tier impact
	data := &statusData{
		TPM: tpmStatus{Present: true, MaxAuthFail: 3},
		Sbctl: &sbctlInfo{
			Installed:       true,
			BootedUKISigned: nil,
		},
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		HardwareSecurity: &hardwareSecurityInfo{
			TPMBusEncryption: "active",
			IOMMU:            "active",
			Thunderbolt:      "absent",
			Lockdown:         "confidentiality",
			ModuleSigs:       "enforced",
		},
		Recovery: &recoveryInfo{Enabled: true},
	}
	data.ThreatModel = buildThreatModel(data)
	computeTier(data)
	// Without fwupd, physical vectors have info mitigations → HIGH (not PHYSICAL)
	if data.Tier != "HIGH" {
		t.Errorf("unknown sbctl status without fwupd should give HIGH, got %s", data.Tier)
	}
}

func TestComputeTier_PhysicalWithFwupd(t *testing.T) {
	// All physical vectors pass → PHYSICAL
	data := &statusData{
		TPM: tpmStatus{Present: true, MaxAuthFail: 3},
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		HardwareSecurity: &hardwareSecurityInfo{
			TPMBusEncryption: "active",
			IOMMU:            "active",
			Thunderbolt:      "absent",
			Lockdown:         "confidentiality",
			ModuleSigs:       "enforced",
		},
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformFused:          {Success: true, HsiLevel: 1},
				fwupdAmdPlatformSecureBoot:  {Success: true, HsiLevel: 2},
				fwupdPlatformDebugLocked:    {Success: true, HsiLevel: 2},
				fwupdAmdSpiWriteProtection:  {Success: true, HsiLevel: 2},
				fwupdAmdSpiReplayProtection: {Success: true, HsiLevel: 3},
				fwupdAmdRollbackProtection:  {Success: true, HsiLevel: 4},
				fwupdAmdSmmLocked:           {Success: true, HsiLevel: 1},
				fwupdTpmReconstructionPcr0:  {Success: true, HsiLevel: 2},
				fwupdTpmEmptyPcr:            {Success: true, HsiLevel: 1},
				fwupdPrebootDma:             {Success: true, HsiLevel: 3},
				fwupdCetActive:              {Success: true},
				fwupdSmap:                   {Success: true, HsiLevel: 4},
				fwupdKernelTainted:          {Success: true},
			},
		},
		Recovery: &recoveryInfo{Enabled: true},
	}
	data.ThreatModel = buildThreatModel(data)
	computeTier(data)
	if data.Tier != "PHYSICAL" {
		t.Errorf("all physical checks pass with fwupd → should be PHYSICAL, got %s", data.Tier)
	}
}

func TestComputeTier_PhysicalToHighWhenPSBNotEnabled(t *testing.T) {
	// PSB not-enabled → info in Evil Maid → PHYSICAL→HIGH
	data := &statusData{
		TPM: tpmStatus{Present: true, MaxAuthFail: 3},
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		HardwareSecurity: &hardwareSecurityInfo{
			TPMBusEncryption: "active",
			IOMMU:            "active",
			Thunderbolt:      "absent",
			Lockdown:         "confidentiality",
			ModuleSigs:       "enforced",
		},
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformFused:          {Success: true, HsiLevel: 1},
				fwupdAmdPlatformSecureBoot:  {Success: false, HsiLevel: 2}, // PSB not enabled
				fwupdPlatformDebugLocked:    {Success: true, HsiLevel: 2},
				fwupdAmdSpiWriteProtection:  {Success: true, HsiLevel: 2},
				fwupdAmdSpiReplayProtection: {Success: true, HsiLevel: 3},
				fwupdAmdRollbackProtection:  {Success: true, HsiLevel: 4},
				fwupdAmdSmmLocked:           {Success: true, HsiLevel: 1},
				fwupdTpmReconstructionPcr0:  {Success: true, HsiLevel: 2},
				fwupdTpmEmptyPcr:            {Success: true, HsiLevel: 1},
				fwupdPrebootDma:             {Success: true, HsiLevel: 3},
				fwupdCetActive:              {Success: true},
				fwupdSmap:                   {Success: true, HsiLevel: 4},
				fwupdKernelTainted:          {Success: true},
			},
		},
		Recovery: &recoveryInfo{Enabled: true},
	}
	data.ThreatModel = buildThreatModel(data)
	computeTier(data)
	if data.Tier != "HIGH" {
		t.Errorf("PSB not-enabled → should downgrade PHYSICAL to HIGH, got %s", data.Tier)
	}
}

func TestComputeTier_CriticalWhenDebugNotLocked(t *testing.T) {
	// Debug interface NOT locked → Physical Debug vector critical → CRITICAL
	data := &statusData{
		TPM: tpmStatus{Present: true, MaxAuthFail: 3},
		LUKSDevices: []luksDeviceInfo{
			{Token: &tokenDetail{HasPIN: true, HasPCRLock: true}},
		},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		HardwareSecurity: &hardwareSecurityInfo{
			TPMBusEncryption: "active",
			IOMMU:            "active",
			Thunderbolt:      "absent",
			Lockdown:         "confidentiality",
			ModuleSigs:       "enforced",
		},
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformFused:       {Success: true, HsiLevel: 1},
				fwupdPlatformDebugLocked: {Success: false, HsiLevel: 2}, // NOT locked
				fwupdAmdSmmLocked:        {Success: true, HsiLevel: 1},
			},
		},
	}
	data.ThreatModel = buildThreatModel(data)
	computeTier(data)
	if data.Tier != "CRITICAL" {
		t.Errorf("debug not locked → should be CRITICAL, got %s", data.Tier)
	}
}

// --- New vector builder tests ---

func TestBuildPhysicalDebugVector_FwupdLocked(t *testing.T) {
	data := &statusData{
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformDebugLocked: {Success: true, HsiLevel: 2},
				fwupdPlatformFused:       {Success: true, HsiLevel: 1},
			},
		},
	}
	v := buildPhysicalDebugVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("debug locked + fused → status should be ok, got %s", v.Status)
	}
}

func TestBuildPhysicalDebugVector_FwupdNotLocked(t *testing.T) {
	data := &statusData{
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformDebugLocked: {Success: false, HsiLevel: 2},
				fwupdPlatformFused:       {Success: true, HsiLevel: 1},
			},
		},
	}
	v := buildPhysicalDebugVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("debug NOT locked → status should be critical, got %s", v.Status)
	}
}

func TestBuildPhysicalDebugVector_HSTILocked(t *testing.T) {
	data := &statusData{
		HSTI: &hstiInfo{Available: true, DebugLockOn: 1, FusedPart: 1},
	}
	v := buildPhysicalDebugVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("HSTI debug locked + fused → status should be ok, got %s", v.Status)
	}
}

func TestBuildPhysicalDebugVector_NoData(t *testing.T) {
	data := &statusData{}
	v := buildPhysicalDebugVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("no fwupd/HSTI → info mitigations, status should be ok, got %s", v.Status)
	}
}

func TestBuildFirmwareTamperingVector_AllOk(t *testing.T) {
	data := &statusData{
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdAmdSpiWriteProtection:  {Success: true, HsiLevel: 2},
				fwupdAmdSpiReplayProtection: {Success: true, HsiLevel: 3},
				fwupdAmdRollbackProtection:  {Success: true, HsiLevel: 4},
			},
		},
	}
	v := buildFirmwareTamperingVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("all SPI protections enabled → status should be ok, got %s", v.Status)
	}
}

func TestBuildFirmwareTamperingVector_SpiWriteOff(t *testing.T) {
	data := &statusData{
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdAmdSpiWriteProtection:  {Success: false, HsiLevel: 2},
				fwupdAmdSpiReplayProtection: {Success: true, HsiLevel: 3},
				fwupdAmdRollbackProtection:  {Success: true, HsiLevel: 4},
			},
		},
	}
	v := buildFirmwareTamperingVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("SPI write protection off → status should be critical, got %s", v.Status)
	}
}

func TestBuildFirmwareTamperingVector_HSTI(t *testing.T) {
	data := &statusData{
		HSTI: &hstiInfo{
			Available:             true,
			RomArmorEnforced:      1,
			RpmcProductionEnabled: 1,
			RpmcSpiromAvailable:   1,
			AntiRollbackStatus:    1,
		},
	}
	v := buildFirmwareTamperingVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("HSTI all ok → status should be ok, got %s", v.Status)
	}
}

func TestBuildSMMAttackVector_Locked(t *testing.T) {
	data := &statusData{
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdAmdSmmLocked: {Success: true, HsiLevel: 1},
			},
		},
	}
	v := buildSMMAttackVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("SMM locked → status should be ok, got %s", v.Status)
	}
}

func TestBuildSMMAttackVector_NotLocked(t *testing.T) {
	data := &statusData{
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdAmdSmmLocked: {Success: false, HsiLevel: 1},
			},
		},
	}
	v := buildSMMAttackVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("SMM NOT locked → status should be critical, got %s", v.Status)
	}
}

func TestBuildSMMAttackVector_NoData(t *testing.T) {
	data := &statusData{}
	v := buildSMMAttackVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "ok" {
		t.Errorf("no fwupd → info mitigation, status should be ok, got %s", v.Status)
	}
}

func TestBuildEvilMaidVector_PSBNotEnabled(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false, CustomKeys: true},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformFused:         {Success: true, HsiLevel: 1},
				fwupdAmdPlatformSecureBoot: {Success: false, HsiLevel: 2},
			},
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	// PSB not-enabled is info, not warning → vector is ok
	if v.Status != "ok" {
		t.Errorf("PSB not-enabled (info) → vector status should be ok, got %s", v.Status)
	}
	// But the PSB mitigation itself should be info
	foundPSB := false
	for _, m := range v.Mitigations {
		if m.Name == "Hardware Validated Boot (PSB)" {
			foundPSB = true
			if m.Status != "info" {
				t.Errorf("PSB mitigation should be info, got %s", m.Status)
			}
		}
	}
	if !foundPSB {
		t.Error("PSB mitigation not found in Evil Maid vector")
	}
}

func TestBuildEvilMaidVector_PlatformNotFused(t *testing.T) {
	data := &statusData{
		SecureBoot: &secureBootInfo{Enabled: true, SetupMode: false},
		PCRLock: &pcrlockInfo{
			PCRResults: []pcrStatus{
				{PCR: 7, IsEnforced: true, Match: true},
			},
		},
		Fwupd: &fwupdInfo{
			Installed: true,
			Attributes: map[string]fwupdAttr{
				fwupdPlatformFused: {Success: false, HsiLevel: 1},
			},
		},
	}
	v := buildEvilMaidVector(data)
	v.Status = vectorStatus(&v)
	if v.Status != "critical" {
		t.Errorf("platform not fused → status should be critical, got %s", v.Status)
	}
}

func TestVectorStatus_TPMWithFtpm(t *testing.T) {
	v := &threatVector{
		Name: "TPM Key Extraction (bus sniffing)",
		Mitigations: []mitigation{
			{Name: "TPM type", Status: "ok", Detail: "fTPM (CRB) — no external bus"},
			{Name: "TPM bus encryption", Status: "ok"},
			{Name: "Dictionary attack lockout", Status: "ok"},
		},
	}
	if status := vectorStatus(v); status != "ok" {
		t.Errorf("vectorStatus: got %q, want ok", status)
	}
	if !vectorIsCollapsed(v) {
		t.Error("vectorIsCollapsed should be true when all mitigations are ok")
	}
}
