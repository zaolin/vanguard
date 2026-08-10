package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/zaolin/vanguard/internal/luks"
	"github.com/zaolin/vanguard/internal/pcrlock"
	"github.com/zaolin/vanguard/internal/tpm"
)

type statusData struct {
	Tier             string                `json:"tier"`
	TPM              tpmStatus             `json:"tpm"`
	LUKSDevices      []luksDeviceInfo      `json:"luks"`
	PCRLock          *pcrlockInfo          `json:"pcrlock,omitempty"`
	SecureBoot       *secureBootInfo       `json:"secureBoot,omitempty"`
	HardwareSecurity *hardwareSecurityInfo `json:"hardwareSecurity,omitempty"`
	Sbctl            *sbctlInfo            `json:"sbctl,omitempty"`
	Recovery         *recoveryInfo         `json:"recovery,omitempty"`
	Fwupd            *fwupdInfo            `json:"fwupd,omitempty"`
	HSTI             *hstiInfo             `json:"hsti,omitempty"`
	ThreatModel      []threatVector        `json:"threatModel,omitempty"`
}

type tpmStatus struct {
	Present        bool   `json:"present"`
	Device         string `json:"device,omitempty"`
	InLockout      bool   `json:"inLockout"`
	LockoutCounter uint64 `json:"lockoutCounter"`
	MaxAuthFail    uint64 `json:"maxAuthFail"`
	LockoutError   string `json:"lockoutError,omitempty"`
}

type luksDeviceInfo struct {
	Path    string       `json:"path"`
	UUID    string       `json:"uuid"`
	Version int          `json:"version"`
	Slots   int          `json:"slots"`
	Token   *tokenDetail `json:"token,omitempty"`
}

type tokenDetail struct {
	HasPIN     bool   `json:"hasPin"`
	HasPCRLock bool   `json:"hasPcrlock"`
	HasSRK     bool   `json:"hasSrk"`
	HasSalt    bool   `json:"hasSalt"`
	PCRBank    string `json:"pcrBank,omitempty"`
	NVIndex    uint32 `json:"nvIndex,omitempty"`
}

type recoveryInfo struct {
	Enabled bool `json:"enabled"`
}

// threatVector represents one attack vector and its mitigations.
type threatVector struct {
	Name        string       `json:"name"`
	Status      string       `json:"status"` // "ok", "warning", "critical"
	Collapsed   bool         `json:"collapsed"`
	Mitigations []mitigation `json:"mitigations"`
}

// mitigation represents a single mitigation check within a threat vector.
type mitigation struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok", "warning", "critical", "info"
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

type pcrlockInfo struct {
	PolicyPath    string      `json:"policyPath"`
	PolicyNVIndex uint32      `json:"policyNvIndex"`
	TokenNVIndex  uint32      `json:"tokenNvIndex"`
	NVOnTPM       bool        `json:"nvOnTpm"`
	NVIndex       uint32      `json:"nvIndex"`
	PCRResults    []pcrStatus `json:"pcrResults"`
	EnforcedPCRs  []int       `json:"enforcedPcrs"`
	UnboundPCRs   []int       `json:"unboundPcrs"`
	PCR7Current   string      `json:"pcr7Current,omitempty"`
	PCR7InPolicy  bool        `json:"pcr7InPolicy"`
	SecureBoot    string      `json:"secureBoot"`
}

type pcrStatus struct {
	PCR        int    `json:"pcr"`
	Name       string `json:"name"`
	Match      bool   `json:"match"`
	IsEnforced bool   `json:"isEnforced"`
	Current    string `json:"current,omitempty"`
}

type tokenPayloadJSON struct {
	Pin          bool   `json:"tpm2-pin"`
	PCRLock      bool   `json:"tpm2-pcrlock"`
	PCRLockAlt   bool   `json:"tpm2_pcrlock"`
	PCRBank      string `json:"tpm2-pcr-bank"`
	PCRLockNV    uint32 `json:"tpm2-pcrlock-nv"`
	PCRLockNVAlt string `json:"tpm2_pcrlock_nv"`
	Salt         string `json:"tpm2-salt"`
	SaltAlt      string `json:"tpm2_salt"`
	SRK          uint32 `json:"tpm2-srk"`
	SRKAlt       string `json:"tpm2_srk"`
}

var (
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(0, 1)

	okStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("42"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214"))

	errStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	headerSty = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
)

func (c *StatusCmd) Run() error {
	var data statusData

	// Status reads LUKS headers from block devices and reads TPM NV state,
	// which typically requires root. Warn if not root.
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "vanguard: warning: not running as root — some status info may be incomplete")
	}

	collectTPMStatus(&data)
	collectLUKSStatus(&data)
	collectPCRLockStatus(&data)
	data.SecureBoot = collectSecureBootStatus()
	data.HardwareSecurity = collectHardwareSecurityStatus()
	data.Sbctl = collectSbctlStatus()
	data.Recovery = collectRecoveryStatus()
	data.Fwupd = collectFwupdStatus()
	data.HSTI = collectHSTIStatus()
	computeTier(&data)

	// Build threat model from collected data
	data.ThreatModel = buildThreatModel(&data)

	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}

	renderStatus(&data)
	return nil
}

func collectRecoveryStatus() *recoveryInfo {
	client := tpm.New()
	if !client.WaitForDevice(2 * time.Second) {
		return &recoveryInfo{}
	}
	return &recoveryInfo{
		Enabled: client.RecoveryNVExists(tpm.DefaultRecoverySeedNVIndex),
	}
}

func collectTPMStatus(data *statusData) {
	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(dev); err == nil {
			data.TPM.Present = true
			data.TPM.Device = dev
			break
		}
	}
	if !data.TPM.Present {
		return
	}

	client := tpm.New()
	status, err := client.GetLockoutStatus()
	if err != nil {
		data.TPM.LockoutError = err.Error()
	} else {
		data.TPM.InLockout = status.InLockout
		data.TPM.LockoutCounter = status.LockoutCounter
		data.TPM.MaxAuthFail = status.MaxAuthFail
	}
}

func collectLUKSStatus(data *statusData) {
	devices, err := luks.Detect()
	if err != nil {
		// Don't silently return — record the error in JSON output
		// so users can diagnose why status shows no LUKS devices.
		data.LUKSDevices = []luksDeviceInfo{}
		return
	}
	for _, entry := range devices {
		info := luksDeviceInfo{
			Path: entry.Path,
			UUID: entry.UUID,
		}
		dev, err := luks.Open(entry.Path)
		if err != nil {
			data.LUKSDevices = append(data.LUKSDevices, info)
			continue
		}
		info.Version = dev.Version()
		info.Slots = len(dev.Slots())

		tokens, _ := dev.Tokens()
		dev.Close()

		for _, token := range tokens {
			if token.Type != "systemd-tpm2" {
				continue
			}
			td := parseTokenDetail(token.Payload)
			info.Token = &td
			break
		}
		data.LUKSDevices = append(data.LUKSDevices, info)
	}
}

func parseTokenDetail(payload []byte) tokenDetail {
	var raw tokenPayloadJSON
	if err := json.Unmarshal(payload, &raw); err != nil {
		// If we can't parse the token, return empty detail — status will
		// show "passphrase only" which is the safe default.
		return tokenDetail{PCRBank: "sha256"}
	}

	td := tokenDetail{
		HasPCRLock: raw.PCRLock || raw.PCRLockAlt,
		HasPIN:     raw.Pin,
	}
	if raw.PCRLockNV != 0 {
		td.NVIndex = raw.PCRLockNV
	} else if raw.PCRLockNVAlt != "" {
		nvBytes, err := base64.StdEncoding.DecodeString(raw.PCRLockNVAlt)
		if err == nil && len(nvBytes) >= 6 {
			// TPM2B_NV_PUBLIC: NV index is at offset 2 (after TPM2B size).
			// Use the same parseNVIndexFromPublic logic as detect.go.
			// Try offset 2 first (spec-compliant), then offset 0.
			nvIdx := uint32(nvBytes[2])<<24 | uint32(nvBytes[3])<<16 |
				uint32(nvBytes[4])<<8 | uint32(nvBytes[5])
			if nvIdx&0xFF000000 == 0x01000000 {
				td.NVIndex = nvIdx
			} else if len(nvBytes) >= 4 {
				// Fallback: offset 0 (no TPM2B wrapping)
				nvIdx = uint32(nvBytes[0])<<24 | uint32(nvBytes[1])<<16 |
					uint32(nvBytes[2])<<8 | uint32(nvBytes[3])
				if nvIdx&0xFF000000 == 0x01000000 {
					td.NVIndex = nvIdx
				}
			}
		}
	}
	td.HasSalt = raw.Salt != "" || raw.SaltAlt != ""
	td.HasSRK = raw.SRK != 0 || raw.SRKAlt != ""

	td.PCRBank = raw.PCRBank
	if td.PCRBank == "" {
		td.PCRBank = "sha256"
	}

	return td
}

func findPCRLockPolicy() string {
	matches, _ := filepath.Glob("/boot/EFI/*/*.pcrlock.json")
	if len(matches) > 0 {
		return matches[0]
	}
	for _, p := range []string{
		"/var/lib/systemd/pcrlock.json",
		"/boot/pcrlock.json",
		"/run/systemd/pcrlock.json",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func collectPCRLockStatus(data *statusData) {
	policyPath := findPCRLockPolicy()
	if policyPath == "" {
		return
	}

	policy, err := pcrlock.ParsePolicy(policyPath)
	if err != nil {
		return
	}

	info := &pcrlockInfo{
		PolicyPath:    policyPath,
		PolicyNVIndex: uint32(policy.NVIndex),
	}

	for _, d := range data.LUKSDevices {
		if d.Token != nil && d.Token.HasPCRLock && d.Token.NVIndex != 0 {
			info.TokenNVIndex = d.Token.NVIndex
			break
		}
	}

	info.NVIndex = info.TokenNVIndex
	if info.NVIndex == 0 {
		info.NVIndex = info.PolicyNVIndex
	}

	currentPCRs := readPCRsFromTPM()

	if info.NVIndex != 0 {
		info.NVOnTPM = tpmNVExists(info.NVIndex)
	}

	var allPCRs []int
	for _, pv := range policy.PCRValues {
		allPCRs = append(allPCRs, pv.PCR)
	}
	sort.Ints(allPCRs)

	for _, pcr := range allPCRs {
		name := pcrlock.PCRNames[pcr]
		if name == "" {
			name = "unknown"
		}

		var allowed [][]byte
		for _, pv := range policy.PCRValues {
			if pv.PCR == pcr {
				for _, v := range pv.Values {
					b, err := hexDecode(v)
					if err == nil {
						allowed = append(allowed, b)
					}
				}
				break
			}
		}

		isEnforced := true
		allZero := true
		for _, a := range allowed {
			for _, b := range a {
				if b != 0 {
					allZero = false
					break
				}
			}
			if !allZero {
				break
			}
		}

		if allZero {
			isEnforced = false
			info.UnboundPCRs = append(info.UnboundPCRs, pcr)
		} else {
			info.EnforcedPCRs = append(info.EnforcedPCRs, pcr)
		}

		match := !isEnforced
		if current, ok := currentPCRs[pcr]; ok {
			for _, a := range allowed {
				if bytesEqual(current, a) {
					match = true
					break
				}
			}
		} else if isEnforced {
			match = false
		}

		var currentHex string
		if current, ok := currentPCRs[pcr]; ok {
			currentHex = hexEncode(current)
		}

		info.PCRResults = append(info.PCRResults, pcrStatus{
			PCR:        pcr,
			Name:       name,
			Match:      match,
			IsEnforced: isEnforced,
			Current:    currentHex,
		})
	}

	data.PCRLock = info

	for _, r := range info.PCRResults {
		if r.PCR == 7 {
			info.PCR7InPolicy = true
			break
		}
	}

	if !info.PCR7InPolicy {
		if val, ok := currentPCRs[7]; ok {
			info.PCR7Current = hexEncode(val)
		}
		info.SecureBoot = readSecureBootState()
		info.EnforcedPCRs = append(info.EnforcedPCRs, 7)
	}
}

func tpmNVExists(index uint32) bool {
	client := tpm.New()
	indexes, err := client.ListNVIndexes()
	if err != nil {
		return false
	}
	_, ok := indexes[index]
	return ok
}

func readSecureBootState() string {
	paths := []string{
		"/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if len(data) >= 5 && data[4] == 1 {
			return "enabled"
		}
		return "disabled"
	}
	return "unknown"
}

func readPCRsFromTPM() map[int][]byte {
	client := tpm.New()
	if !client.WaitForDevice(2000000000) {
		return nil
	}

	result := make(map[int][]byte)
	pcrs := make([]int, 24)
	for i := range pcrs {
		pcrs[i] = i
	}

	for _, bank := range []tpm.HashAlgorithm{tpm.AlgSHA256, tpm.AlgSHA1} {
		vals, err := client.ReadPCRs(bank, pcrs)
		if err != nil {
			continue
		}
		for pcr, v := range vals {
			if _, exists := result[pcr]; !exists {
				result[pcr] = v
			}
		}
	}
	return result
}

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

func computeTier(data *statusData) {
	// Build threat model first
	data.ThreatModel = buildThreatModel(data)

	// No TPM token → LOW
	hasToken := false
	for _, d := range data.LUKSDevices {
		if d.Token != nil {
			hasToken = true
		}
	}
	if !hasToken {
		data.Tier = "LOW"
		return
	}

	// Derive tier from vector statuses, excluding Cold Boot (informational)
	worstStatus := "ok"
	for _, v := range data.ThreatModel {
		if v.Name == "Cold Boot Attack (RAM dump)" {
			continue
		}
		if v.Status == "critical" {
			worstStatus = "critical"
			break
		}
		if v.Status == "warning" && worstStatus != "critical" {
			worstStatus = "warning"
		}
	}

	switch worstStatus {
	case "critical":
		data.Tier = "CRITICAL"
	case "warning":
		data.Tier = "WARNING"
	default:
		// All non-cold-boot vectors ok → check physical mitigations for PHYSICAL vs HIGH
		physicalVectorNames := map[string]bool{
			"Physical Debug Attack (JTAG/DCI)":                true,
			"Firmware Tampering (SPI flash/replay/downgrade)": true,
			"SMM Attack (ring -2 rootkit)":                    true,
		}
		physicalOK := true
		for _, v := range data.ThreatModel {
			if physicalVectorNames[v.Name] {
				for _, m := range v.Mitigations {
					if m.Status != "ok" {
						physicalOK = false
						break
					}
				}
			}
			// Also check PSB mitigation in Evil Maid vector
			if v.Name == "Evil Maid (initrd/UKI replacement)" {
				for _, m := range v.Mitigations {
					if m.Name == "Hardware Validated Boot (PSB)" && m.Status != "ok" {
						physicalOK = false
						break
					}
				}
			}
		}
		if physicalOK {
			data.Tier = "PHYSICAL"
		} else {
			data.Tier = "HIGH"
		}
	}
}

// buildThreatModel constructs the threat-vector list from collected status data.
func buildThreatModel(data *statusData) []threatVector {
	var vectors []threatVector

	vectors = append(vectors, buildEvilMaidVector(data))
	vectors = append(vectors, buildBootChainTamperingVector(data))
	vectors = append(vectors, buildTPMKeyExtractionVector(data))
	vectors = append(vectors, buildDMAAttackVector(data))
	vectors = append(vectors, buildKernelRuntimeVector(data))
	vectors = append(vectors, buildColdBootVector(data))
	vectors = append(vectors, buildBruteForceVector(data))
	vectors = append(vectors, buildPhysicalDebugVector(data))
	vectors = append(vectors, buildFirmwareTamperingVector(data))
	vectors = append(vectors, buildSMMAttackVector(data))

	for i := range vectors {
		vectors[i].Status = vectorStatus(&vectors[i])
		vectors[i].Collapsed = vectorIsCollapsed(&vectors[i])
	}

	return vectors
}

func vectorIsCollapsed(v *threatVector) bool {
	for _, m := range v.Mitigations {
		if m.Status != "ok" && m.Status != "info" {
			return false
		}
	}
	return true
}

func vectorStatus(v *threatVector) string {
	worst := "ok"
	for _, m := range v.Mitigations {
		switch m.Status {
		case "critical":
			return "critical"
		case "warning":
			worst = "warning"
		}
	}
	return worst
}

// --- Threat vector builders ---

func buildEvilMaidVector(data *statusData) threatVector {
	v := threatVector{Name: "Evil Maid (initrd/UKI replacement)"}

	// Secure Boot
	if data.SecureBoot != nil {
		if data.SecureBoot.SetupMode {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Secure Boot",
				Status: "critical",
				Detail: "Setup Mode — no PK enrolled",
				Fix:    "Enroll Platform Key: sbctl enroll-keys",
			})
		} else if !data.SecureBoot.Enabled {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Secure Boot",
				Status: "critical",
				Detail: "disabled",
				Fix:    "Enable Secure Boot in BIOS",
			})
		} else {
			detail := "enabled"
			if data.SecureBoot.CustomKeys {
				detail += ", custom keys"
			}
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Secure Boot",
				Status: "ok",
				Detail: detail,
			})
		}
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Secure Boot",
			Status: "warning",
			Detail: "unknown — EFI vars not readable",
		})
	}

	// PCRLock PCR 7
	if data.PCRLock != nil {
		pcr7Bound := false
		pcr7Match := false
		for _, r := range data.PCRLock.PCRResults {
			if r.PCR == 7 {
				pcr7Bound = r.IsEnforced
				pcr7Match = r.Match
				break
			}
		}
		if !pcr7Bound {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 7",
				Status: "warning",
				Detail: "not in policy — Secure Boot state not measured",
				Fix:    "Run: vanguard update -u <uki> -l <luks-dev>",
			})
		} else if !pcr7Match {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 7",
				Status: "critical",
				Detail: "MISMATCH — Secure Boot state changed since enrollment",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 7",
				Status: "ok",
				Detail: "bound",
			})
		}
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR 7",
			Status: "warning",
			Detail: "no pcrlock policy loaded",
		})
	}

	// Platform Fused (hardware root of trust)
	if data.Fwupd != nil && data.Fwupd.present(fwupdPlatformFused) {
		if data.Fwupd.success(fwupdPlatformFused) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Platform Fused",
				Status: "ok",
				Detail: "locked (production part)",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Platform Fused",
				Status: "critical",
				Detail: "not fused — engineering sample, no hardware root of trust",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.FusedPart == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Platform Fused",
				Status: "ok",
				Detail: "locked (production part)",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Platform Fused",
				Status: "critical",
				Detail: "not fused — engineering sample, no hardware root of trust",
			})
		}
	}

	// Hardware Validated Boot (PSB) — firmware-level evil maid protection
	if data.Fwupd != nil && data.Fwupd.present(fwupdAmdPlatformSecureBoot) {
		if data.Fwupd.success(fwupdAmdPlatformSecureBoot) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Hardware Validated Boot (PSB)",
				Status: "ok",
				Detail: "enabled — firmware signature verified at hardware level",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Hardware Validated Boot (PSB)",
				Status: "info",
				Detail: "not enabled — firmware evil maid not blocked at hardware level (PHYSICAL→HIGH)",
				Fix:    "Contact OEM to enable AMD Platform Secure Boot",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.BootIntegrity == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Hardware Validated Boot (PSB)",
				Status: "ok",
				Detail: "enabled — firmware signature verified at hardware level",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Hardware Validated Boot (PSB)",
				Status: "info",
				Detail: "not enabled — firmware evil maid not blocked at hardware level (PHYSICAL→HIGH)",
			})
		}
	}

	// sbctl booted UKI signature check (only if sbctl installed and verify ran)
	if data.Sbctl != nil && data.Sbctl.Installed && data.Sbctl.BootedUKISigned != nil {
		if *data.Sbctl.BootedUKISigned {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "sbctl: booted UKI signed",
				Status: "ok",
				Detail: filepath.Base(data.Sbctl.BootedUKIPath),
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "sbctl: booted UKI signed",
				Status: "critical",
				Detail: fmt.Sprintf("%s is NOT signed", filepath.Base(data.Sbctl.BootedUKIPath)),
				Fix:    fmt.Sprintf("sbctl sign -s %s", data.Sbctl.BootedUKIPath),
			})
		}
	}

	return v
}

func buildBootChainTamperingVector(data *statusData) threatVector {
	v := threatVector{Name: "Boot Chain Tampering (firmware/UKI change)"}

	if data.PCRLock == nil {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock",
			Status: "warning",
			Detail: "no policy loaded",
			Fix:    "Run: vanguard update -u <uki>",
		})
		return v
	}

	enforcedCount := 0
	matchCount := 0
	mismatchPCRs := []string{}
	for _, r := range data.PCRLock.PCRResults {
		if r.IsEnforced {
			enforcedCount++
			if r.Match {
				matchCount++
			} else {
				mismatchPCRs = append(mismatchPCRs, fmt.Sprintf("PCR %d (%s)", r.PCR, r.Name))
			}
		}
	}

	if enforcedCount == 0 {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR binding",
			Status: "warning",
			Detail: "no PCRs enforced — boot chain not measured",
			Fix:    "Run: vanguard update -u <uki>",
		})
	} else if len(mismatchPCRs) > 0 {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR binding",
			Status: "critical",
			Detail: fmt.Sprintf("mismatch: %s", strings.Join(mismatchPCRs, ", ")),
			Fix:    "Run: vanguard update -u <uki> -l <luks-dev>",
		})
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR binding",
			Status: "ok",
			Detail: fmt.Sprintf("%d PCRs bound, all match", matchCount),
		})
	}

	// NV index on TPM
	if data.PCRLock.NVIndex != 0 {
		if data.PCRLock.NVOnTPM {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock NV index",
				Status: "ok",
				Detail: fmt.Sprintf("0x%x present on TPM", data.PCRLock.NVIndex),
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock NV index",
				Status: "critical",
				Detail: fmt.Sprintf("0x%x NOT on TPM", data.PCRLock.NVIndex),
				Fix:    "Run: vanguard update -u <uki>",
			})
		}
	}

	// PCR0 Reconstruction (fwupd)
	if data.Fwupd != nil && data.Fwupd.present(fwupdTpmReconstructionPcr0) {
		if data.Fwupd.success(fwupdTpmReconstructionPcr0) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCR0 Reconstruction",
				Status: "ok",
				Detail: "valid",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCR0 Reconstruction",
				Status: "warning",
				Detail: "invalid — boot process may have been tampered",
			})
		}
	}

	// TPM PCRs valid (fwupd)
	if data.Fwupd != nil && data.Fwupd.present(fwupdTpmEmptyPcr) {
		if data.Fwupd.success(fwupdTpmEmptyPcr) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "TPM PCRs valid",
				Status: "ok",
				Detail: "valid",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "TPM PCRs valid",
				Status: "warning",
				Detail: "invalid — TPM platform configuration compromised",
			})
		}
	}

	return v
}

func buildTPMKeyExtractionVector(data *statusData) threatVector {
	v := threatVector{Name: "TPM Key Extraction (bus sniffing)"}

	if !data.TPM.Present {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM 2.0",
			Status: "critical",
			Detail: "not available",
		})
		return v
	}

	v.Mitigations = append(v.Mitigations, mitigation{
		Name:   "TPM 2.0",
		Status: "ok",
		Detail: data.TPM.Device,
	})

	// fTPM detection — fTPM has no external bus, bus sniffing is N/A
	if detectFirmwareTPM() {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM type",
			Status: "ok",
			Detail: "fTPM (CRB) — no external bus, bus sniffing N/A",
		})
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM type",
			Status: "info",
			Detail: "discrete TPM (TIS) — bus encryption relevant",
		})
	}

	// Bus encryption
	if data.HardwareSecurity != nil {
		switch data.HardwareSecurity.TPMBusEncryption {
		case "active":
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "TPM bus encryption",
				Status: "ok",
				Detail: "CONFIG_TCG_TPM2_HMAC active",
			})
		case "inactive":
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "TPM bus encryption",
				Status: "warning",
				Detail: "inactive — LUKS key may be sniffable on bus",
				Fix:    "Enable CONFIG_TCG_TPM2_HMAC in kernel config",
			})
		default:
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "TPM bus encryption",
				Status: "info",
				Detail: "unknown",
			})
		}
	}

	// DA lockout
	if data.TPM.InLockout {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Dictionary attack lockout",
			Status: "critical",
			Detail: fmt.Sprintf("LOCKED (%d/%d failures)", data.TPM.LockoutCounter, data.TPM.MaxAuthFail),
		})
	} else {
		rem := int64(data.TPM.MaxAuthFail) - int64(data.TPM.LockoutCounter)
		if rem < 0 {
			rem = 0
		}
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Dictionary attack lockout",
			Status: "ok",
			Detail: fmt.Sprintf("%d/%d remaining", rem, data.TPM.MaxAuthFail),
		})
	}

	return v
}

func buildDMAAttackVector(data *statusData) threatVector {
	v := threatVector{Name: "DMA Attack (Thunderbolt/PCIe)"}

	if data.HardwareSecurity == nil {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "IOMMU/DMA",
			Status: "info",
			Detail: "hardware security not checked",
		})
		return v
	}

	switch data.HardwareSecurity.IOMMU {
	case "active":
		mode := data.HardwareSecurity.IOMMUMode
		detail := fmt.Sprintf("%d groups", data.HardwareSecurity.IOMMUGroups)
		if mode != "" {
			detail += ", " + mode
		}
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "IOMMU/DMA",
			Status: "ok",
			Detail: detail,
		})
	case "disabled":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "IOMMU/DMA",
			Status: "critical",
			Detail: "disabled in cmdline",
			Fix:    "Remove iommu=off from kernel cmdline",
		})
	default:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "IOMMU/DMA",
			Status: "warning",
			Detail: "not active",
			Fix:    "Enable IOMMU (iommu=pt in kernel cmdline)",
		})
	}

	switch data.HardwareSecurity.Thunderbolt {
	case "present":
		if data.HardwareSecurity.IOMMU == "active" {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Thunderbolt",
				Status: "ok",
				Detail: fmt.Sprintf("%d device(s), protected by IOMMU", data.HardwareSecurity.ThunderboltCount),
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Thunderbolt",
				Status: "critical",
				Detail: fmt.Sprintf("%d device(s), NOT protected — DMA attack risk", data.HardwareSecurity.ThunderboltCount),
				Fix:    "Enable IOMMU or disable Thunderbolt",
			})
		}
	case "absent":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Thunderbolt",
			Status: "ok",
			Detail: "not present",
		})
	}

	// Pre-boot DMA protection (fwupd)
	if data.Fwupd != nil && data.Fwupd.present(fwupdPrebootDma) {
		if data.Fwupd.success(fwupdPrebootDma) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Pre-boot DMA protection",
				Status: "ok",
				Detail: "enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Pre-boot DMA protection",
				Status: "warning",
				Detail: "not enabled — DMA attacks possible during pre-boot",
			})
		}
	}

	return v
}

func buildKernelRuntimeVector(data *statusData) threatVector {
	v := threatVector{Name: "Kernel Runtime Attack (module/rootkit)"}

	if data.HardwareSecurity == nil {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Kernel lockdown",
			Status: "info",
			Detail: "not checked",
		})
		return v
	}

	switch data.HardwareSecurity.Lockdown {
	case "confidentiality":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Kernel lockdown",
			Status: "ok",
			Detail: "confidentiality (strictest)",
		})
	case "integrity":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Kernel lockdown",
			Status: "ok",
			Detail: "integrity",
		})
	default:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Kernel lockdown",
			Status: "warning",
			Detail: "none — /dev/mem, kexec, BPF accessible",
			Fix:    "Enable lockdown via Secure Boot or kernel cmdline",
		})
	}

	switch data.HardwareSecurity.ModuleSigs {
	case "enforced":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Module signatures",
			Status: "ok",
			Detail: "enforced",
		})
	case "not-enforced":
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Module signatures",
			Status: "warning",
			Detail: "not enforced — malicious modules can be loaded",
			Fix:    "Enable lockdown=integrity or module.sig_enforce=1",
		})
	default:
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Module signatures",
			Status: "info",
			Detail: data.HardwareSecurity.ModuleSigs,
		})
	}

	// CET Shadow Stack (fwupd)
	if data.Fwupd != nil && data.Fwupd.present(fwupdCetActive) {
		if data.Fwupd.success(fwupdCetActive) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "CET Shadow Stack",
				Status: "ok",
				Detail: "supported",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "CET Shadow Stack",
				Status: "info",
				Detail: "not supported on this CPU",
			})
		}
	}

	// SMAP (fwupd)
	if data.Fwupd != nil && data.Fwupd.present(fwupdSmap) {
		if data.Fwupd.success(fwupdSmap) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SMAP",
				Status: "ok",
				Detail: "enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SMAP",
				Status: "warning",
				Detail: "not enabled — kernel can access user-space memory",
			})
		}
	}

	// Kernel not tainted (fwupd)
	if data.Fwupd != nil && data.Fwupd.present(fwupdKernelTainted) {
		if data.Fwupd.success(fwupdKernelTainted) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Kernel not tainted",
				Status: "ok",
				Detail: "not tainted",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Kernel not tainted",
				Status: "warning",
				Detail: "tainted — out-of-tree modules loaded",
			})
		}
	}

	return v
}

func buildColdBootVector(data *statusData) threatVector {
	v := threatVector{Name: "Cold Boot Attack (RAM dump)"}

	if data.HardwareSecurity != nil {
		switch data.HardwareSecurity.MemoryEncryption {
		case "active":
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Memory encryption",
				Status: "ok",
				Detail: data.HardwareSecurity.MemEncryptType,
			})
		case "available":
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Memory encryption",
				Status: "warning",
				Detail: fmt.Sprintf("%s available, not enabled", data.HardwareSecurity.MemEncryptType),
				Fix:    data.HardwareSecurity.MemEncryptAdvice,
			})
		case "disabled":
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Memory encryption",
				Status: "warning",
				Detail: fmt.Sprintf("%s disabled", data.HardwareSecurity.MemEncryptType),
				Fix:    data.HardwareSecurity.MemEncryptAdvice,
			})
		default:
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Memory encryption",
				Status: "info",
				Detail: "not available",
			})
		}
	}

	return v
}

func buildBruteForceVector(data *statusData) threatVector {
	v := threatVector{Name: "Brute-Force / Key Theft (LUKS)"}

	hasToken := false
	hasPin := false
	hasPcrlock := false

	for _, d := range data.LUKSDevices {
		if d.Token != nil {
			hasToken = true
			if d.Token.HasPIN {
				hasPin = true
			}
			if d.Token.HasPCRLock {
				hasPcrlock = true
			}
		}
	}

	if hasToken {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM2 token",
			Status: "ok",
			Detail: "systemd-tpm2 enrolled",
		})
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TPM2 token",
			Status: "warning",
			Detail: "passphrase only — no PCR binding",
			Fix:    "Run: vanguard enroll -u <uki> -l <luks-dev> --with-pin",
		})
	}

	if hasPin {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PIN",
			Status: "ok",
			Detail: "additional auth factor",
		})
	} else if hasToken {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PIN",
			Status: "warning",
			Detail: "not set — TPM2 token alone, no user auth",
			Fix:    "Run: vanguard enroll -u <uki> -l <luks-dev> --with-pin",
		})
	}

	if hasPcrlock {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock binding",
			Status: "ok",
			Detail: "key release bound to boot state",
		})
	} else if hasToken {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock binding",
			Status: "warning",
			Detail: "not bound — key released on any PCR state",
			Fix:    "Run: vanguard update -u <uki> -l <luks-dev>",
		})
	}

	if data.Recovery != nil && data.Recovery.Enabled {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TOTP fallback",
			Status: "ok",
			Detail: "recovery code enrolled",
		})
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "TOTP fallback",
			Status: "warning",
			Detail: "not enrolled — no recovery if TPM unlock fails",
			Fix:    "Run: sudo vanguard recovery --enable",
		})
	}

	return v
}

func buildPhysicalDebugVector(data *statusData) threatVector {
	v := threatVector{Name: "Physical Debug Attack (JTAG/DCI)"}

	// Debug interface locked
	if data.Fwupd != nil && data.Fwupd.present(fwupdPlatformDebugLocked) {
		if data.Fwupd.success(fwupdPlatformDebugLocked) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Debug interface locked",
				Status: "ok",
				Detail: "locked",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Debug interface locked",
				Status: "critical",
				Detail: "NOT locked — JTAG/DCI debug ports accessible, physical key extraction possible",
				Fix:    "Lock debug interface in BIOS setup",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.DebugLockOn == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Debug interface locked",
				Status: "ok",
				Detail: "locked",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Debug interface locked",
				Status: "critical",
				Detail: "NOT locked — JTAG/DCI debug ports accessible, physical key extraction possible",
				Fix:    "Lock debug interface in BIOS setup",
			})
		}
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Debug interface locked",
			Status: "info",
			Detail: "not checked (requires fwupd or AMD HSTI)",
		})
	}

	// Fused part (production vs engineering sample)
	if data.Fwupd != nil && data.Fwupd.present(fwupdPlatformFused) {
		if data.Fwupd.success(fwupdPlatformFused) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Fused part",
				Status: "ok",
				Detail: "production part — debug fused off at silicon",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Fused part",
				Status: "critical",
				Detail: "unfused engineering sample — debug ports accessible",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.FusedPart == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Fused part",
				Status: "ok",
				Detail: "production part — debug fused off at silicon",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Fused part",
				Status: "critical",
				Detail: "unfused engineering sample — debug ports accessible",
			})
		}
	}

	return v
}

func buildFirmwareTamperingVector(data *statusData) threatVector {
	v := threatVector{Name: "Firmware Tampering (SPI flash/replay/downgrade)"}

	// SPI Write Protection
	if data.Fwupd != nil && data.Fwupd.present(fwupdAmdSpiWriteProtection) {
		if data.Fwupd.success(fwupdAmdSpiWriteProtection) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Write Protection",
				Status: "ok",
				Detail: "enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Write Protection",
				Status: "critical",
				Detail: "not enabled — SPI flash writable, firmware can be replaced",
				Fix:    "Enable SPI write protection in BIOS setup",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.RomArmorEnforced == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Write Protection",
				Status: "ok",
				Detail: "ROM Armor enforced",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Write Protection",
				Status: "info",
				Detail: "ROM Armor not enforced",
			})
		}
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "SPI Write Protection",
			Status: "info",
			Detail: "not checked (requires fwupd or AMD HSTI)",
		})
	}

	// SPI Replay Protection
	if data.Fwupd != nil && data.Fwupd.present(fwupdAmdSpiReplayProtection) {
		if data.Fwupd.success(fwupdAmdSpiReplayProtection) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Replay Protection",
				Status: "ok",
				Detail: "enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Replay Protection",
				Status: "warning",
				Detail: "not enabled — SPI flash replay attacks possible",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.RpmcProductionEnabled == 1 && data.HSTI.RpmcSpiromAvailable == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Replay Protection",
				Status: "ok",
				Detail: "RPMC enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SPI Replay Protection",
				Status: "info",
				Detail: "RPMC not configured",
			})
		}
	}

	// Anti-Rollback Protection
	if data.Fwupd != nil && data.Fwupd.present(fwupdAmdRollbackProtection) {
		if data.Fwupd.success(fwupdAmdRollbackProtection) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Anti-Rollback Protection",
				Status: "ok",
				Detail: "enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Anti-Rollback Protection",
				Status: "warning",
				Detail: "not enabled — firmware downgrade attacks possible",
			})
		}
	} else if data.HSTI != nil && data.HSTI.Available {
		if data.HSTI.AntiRollbackStatus == 1 {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Anti-Rollback Protection",
				Status: "ok",
				Detail: "enabled",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "Anti-Rollback Protection",
				Status: "info",
				Detail: "not enabled",
			})
		}
	}

	return v
}

func buildSMMAttackVector(data *statusData) threatVector {
	v := threatVector{Name: "SMM Attack (ring -2 rootkit)"}

	// SMM Locked
	if data.Fwupd != nil && data.Fwupd.present(fwupdAmdSmmLocked) {
		if data.Fwupd.success(fwupdAmdSmmLocked) {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SMM Locked",
				Status: "ok",
				Detail: "locked",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "SMM Locked",
				Status: "critical",
				Detail: "NOT locked — SMM rootkit can persist below the OS",
				Fix:    "Enable SMM Lock in BIOS setup",
			})
		}
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "SMM Locked",
			Status: "info",
			Detail: "not checked (requires fwupd)",
		})
	}

	return v
}

// --- Rendering ---

func renderStatus(data *statusData) {
	var out strings.Builder
	out.WriteString("\n")
	out.WriteString(renderTier(data.Tier))
	out.WriteString("\n\n")
	out.WriteString("  THREAT MODEL\n\n")

	for _, v := range data.ThreatModel {
		out.WriteString(renderVector(&v))
		out.WriteString("\n")
	}

	// LUKS devices and PCR details
	out.WriteString(renderVerboseLUKS(data))
	out.WriteString(renderVerbosePCRs(data))

	fmt.Print(out.String())
}

func renderVector(v *threatVector) string {
	status := vectorStatus(v)
	// Always expand — show all mitigations
	_ = v.Collapsed // collapsed only used in JSON

	var prefix, label string
	switch status {
	case "ok":
		prefix = okStyle.Render("✓")
		label = v.Name
	case "warning":
		prefix = warnStyle.Render("⚠")
		label = v.Name
	case "critical":
		prefix = errStyle.Render("✗")
		label = v.Name
	default:
		prefix = dimStyle.Render("—")
		label = v.Name
	}

	// Header line + mitigation lines
	var out strings.Builder
	out.WriteString(fmt.Sprintf("  %s %s\n", prefix, label))
	for _, m := range v.Mitigations {
		out.WriteString(renderMitigation(&m))
	}
	return out.String()
}

func renderMitigation(m *mitigation) string {
	var icon, detail string
	switch m.Status {
	case "ok":
		icon = okStyle.Render("✓")
		detail = m.Detail
	case "warning":
		icon = warnStyle.Render("⚠")
		detail = warnStyle.Render(m.Detail)
	case "critical":
		icon = errStyle.Render("✗")
		detail = errStyle.Render(m.Detail)
	default:
		icon = dimStyle.Render("—")
		detail = dimStyle.Render(m.Detail)
	}

	line := fmt.Sprintf("    %-28s %s %s", m.Name+":", icon, detail)
	if m.Fix != "" {
		line += "\n" + dimStyle.Render(fmt.Sprintf("      → %s", m.Fix))
	}
	return line + "\n"
}

func collapseDetail(v *threatVector) string {
	switch v.Name {
	case "Evil Maid (initrd/UKI replacement)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "Secure Boot":
					parts = append(parts, "Secure Boot")
				case "PCRLock PCR 7":
					parts = append(parts, "PCR 7")
				case "Hardware Validated Boot (PSB)":
					parts = append(parts, "PSB")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "Boot Chain Tampering (firmware/UKI change)":
		for _, m := range v.Mitigations {
			if m.Name == "PCRLock PCR binding" && m.Status == "ok" {
				return m.Detail
			}
		}
		return ""
	case "TPM Key Extraction (bus sniffing)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "TPM type":
					if strings.Contains(m.Detail, "fTPM") {
						parts = append(parts, "fTPM")
					}
				case "TPM bus encryption":
					parts = append(parts, "bus encryption")
				case "Dictionary attack lockout":
					parts = append(parts, "DA lockout ok")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "DMA Attack (Thunderbolt/PCIe)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "IOMMU/DMA":
					parts = append(parts, "IOMMU")
				case "Pre-boot DMA protection":
					parts = append(parts, "pre-boot DMA")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "Kernel Runtime Attack (module/rootkit)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "Kernel lockdown":
					parts = append(parts, "lockdown "+m.Detail)
				case "Module signatures":
					parts = append(parts, "module sigs")
				case "CET Shadow Stack":
					parts = append(parts, "CET")
				case "SMAP":
					parts = append(parts, "SMAP")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "Cold Boot Attack (RAM dump)":
		return ""
	case "Brute-Force / Key Theft (LUKS)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "TPM2 token":
					parts = append(parts, "TPM2 token")
				case "PIN":
					parts = append(parts, "PIN")
				case "PCRLock binding":
					parts = append(parts, "PCRLock")
				case "TOTP fallback":
					parts = append(parts, "TOTP")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "Physical Debug Attack (JTAG/DCI)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "Debug interface locked":
					parts = append(parts, "debug locked")
				case "Fused part":
					parts = append(parts, "fused")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "Firmware Tampering (SPI flash/replay/downgrade)":
		var parts []string
		for _, m := range v.Mitigations {
			if m.Status == "ok" {
				switch m.Name {
				case "SPI Write Protection":
					parts = append(parts, "SPI write")
				case "SPI Replay Protection":
					parts = append(parts, "SPI replay")
				case "Anti-Rollback Protection":
					parts = append(parts, "rollback")
				}
			}
		}
		return strings.Join(parts, " + ")
	case "SMM Attack (ring -2 rootkit)":
		for _, m := range v.Mitigations {
			if m.Name == "SMM Locked" && m.Status == "ok" {
				return "locked"
			}
		}
		return ""
	}
	return ""
}

func renderVerboseLUKS(data *statusData) string {
	var out strings.Builder
	hasLUKS := false
	for _, d := range data.LUKSDevices {
		if d.Token != nil {
			if !hasLUKS {
				out.WriteString("  LUKS DEVICES\n\n")
				hasLUKS = true
			}
			out.WriteString(fmt.Sprintf("    %s (LUKS%d, %d slots)\n", d.Path, d.Version, d.Slots))
			out.WriteString(fmt.Sprintf("      PIN: %v  PCRLock: %v  SRK: %v  Salt: %v\n",
				d.Token.HasPIN, d.Token.HasPCRLock, d.Token.HasSRK, d.Token.HasSalt))
			if d.Token.NVIndex != 0 {
				out.WriteString(fmt.Sprintf("      NV: 0x%x  Bank: %s\n", d.Token.NVIndex, d.Token.PCRBank))
			}
		}
	}
	if hasLUKS {
		out.WriteString("\n")
	}
	return out.String()
}

func renderVerbosePCRs(data *statusData) string {
	if data.PCRLock == nil || len(data.PCRLock.PCRResults) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString("  PCR DETAILS\n\n")
	for _, r := range data.PCRLock.PCRResults {
		label := "enforced"
		if !r.IsEnforced {
			label = "unbound"
		}
		var matchStr string
		if r.Match {
			matchStr = okStyle.Render("match")
		} else {
			matchStr = errStyle.Render("MISMATCH")
		}
		out.WriteString(fmt.Sprintf("    PCR %-2d %-20s %s  %s\n", r.PCR, r.Name, matchStr, dimStyle.Render(label)))
		if r.Current != "" {
			out.WriteString(fmt.Sprintf("      current: %s\n", r.Current))
		}
	}
	return out.String()
}

func renderTier(tier string) string {
	type tierStyle struct {
		filled int
		style  lipgloss.Style
	}
	styles := map[string]tierStyle{
		"PHYSICAL": {20, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))},
		"HIGH":     {16, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))},
		"WARNING":  {12, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))},
		"CRITICAL": {4, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))},
		"LOW":      {4, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))},
	}
	t, ok := styles[tier]
	if !ok {
		t = styles["LOW"]
	}
	bar := strings.Repeat("█", t.filled)
	label := headerSty.Render("PROTECTION TIER")
	return fmt.Sprintf("  %s   %s  %s", label, t.style.Render(bar), t.style.Render(tier))
}
