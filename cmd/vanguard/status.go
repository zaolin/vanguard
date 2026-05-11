package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/zaolin/vanguard/internal/luks"
	"github.com/zaolin/vanguard/internal/pcrlock"
	"github.com/zaolin/vanguard/internal/tpm"
)

type StatusCmd struct {
	JSON    bool `help:"Machine-readable JSON output"`
	Verbose bool `short:"v" help:"Show full PCR hash values"`
}

type statusData struct {
	Tier        string           `json:"tier"`
	TPM         tpmStatus        `json:"tpm"`
	LUKSDevices []luksDeviceInfo `json:"luks"`
	PCRLock     *pcrlockInfo     `json:"pcrlock,omitempty"`
}

type tpmStatus struct {
	Present        bool   `json:"present"`
	Device         string `json:"device,omitempty"`
	InLockout      bool   `json:"inLockout"`
	LockoutCounter uint64 `json:"lockoutCounter"`
	MaxAuthFail    uint64 `json:"maxAuthFail"`
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

	tierHigh  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	tierWarn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	tierMed   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	tierLow   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	headerSty = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
)

func (c *StatusCmd) Run() error {
	var data statusData

	collectTPMStatus(&data)
	collectLUKSStatus(&data)
	collectPCRLockStatus(&data)
	computeTier(&data)

	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}

	renderStatus(&data, c.Verbose)
	return nil
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
	if err == nil {
		data.TPM.InLockout = status.InLockout
		data.TPM.LockoutCounter = status.LockoutCounter
		data.TPM.MaxAuthFail = status.MaxAuthFail
	}
}

func collectLUKSStatus(data *statusData) {
	devices, err := luks.Detect()
	if err != nil {
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
	json.Unmarshal(payload, &raw)

	td := tokenDetail{
		HasPCRLock: raw.PCRLock || raw.PCRLockAlt,
		HasPIN:     raw.Pin,
	}
	if raw.PCRLockNV != 0 {
		td.NVIndex = raw.PCRLockNV
	} else if raw.PCRLockNVAlt != "" {
		nvBytes, err := base64Decode(raw.PCRLockNVAlt)
		if err == nil && len(nvBytes) >= 4 {
			td.NVIndex = uint32(nvBytes[0])<<24 | uint32(nvBytes[1])<<16 |
				uint32(nvBytes[2])<<8 | uint32(nvBytes[3])
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

func base64Decode(s string) ([]byte, error) {
	dst := make([]byte, len(s))
	n, err := base64DecodeInto(dst, []byte(s))
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func base64DecodeInto(dst, src []byte) (int, error) {
	var buf [4]byte
	var writeIdx, i int
	table := [256]byte{}
	for j := 0; j < 26; j++ {
		table['A'+j] = byte(j)
	}
	for j := 0; j < 26; j++ {
		table['a'+j] = byte(26 + j)
	}
	for j := 0; j < 10; j++ {
		table['0'+j] = byte(52 + j)
	}
	table['+'] = 62
	table['/'] = 63
	table['='] = 0xFF

	for _, c := range src {
		if c >= 128 || table[c] == 0 && c != 'A' && c != '=' {
			continue
		}
		if c == '=' {
			break
		}
		buf[i] = table[c]
		i++
		if i == 4 {
			dst[writeIdx] = buf[0]<<2 | buf[1]>>4
			writeIdx++
			dst[writeIdx] = buf[1]<<4 | buf[2]>>2
			writeIdx++
			dst[writeIdx] = buf[2]<<6 | buf[3]
			writeIdx++
			i = 0
		}
	}
	if i == 2 {
		dst[writeIdx] = buf[0]<<2 | buf[1]>>4
		writeIdx++
	} else if i == 3 {
		dst[writeIdx] = buf[0]<<2 | buf[1]>>4
		writeIdx++
		dst[writeIdx] = buf[1]<<4 | buf[2]>>2
		writeIdx++
	}
	return writeIdx, nil
}

func collectPCRLockStatus(data *statusData) {
	searchPaths := []string{
		"/var/lib/systemd/pcrlock.json",
		"/boot/pcrlock.json",
		"/run/systemd/pcrlock.json",
	}
	var policyPath string
	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			policyPath = p
			break
		}
	}
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

func bytesEqual(a, b []byte) bool {
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

func hexDecode(s string) ([]byte, error) {
	dst := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b := hexVal(s[i])<<4 | hexVal(s[i+1])
		dst[i/2] = b
	}
	return dst, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

func hexEncode(b []byte) string {
	const h = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = h[v>>4]
		dst[i*2+1] = h[v&0x0f]
	}
	return string(dst)
}

func computeTier(data *statusData) {
	hasToken := false
	hasPin := false
	hasPcrlock := false
	pcrsOK := true

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

	if data.PCRLock != nil {
		for _, r := range data.PCRLock.PCRResults {
			if r.IsEnforced && !r.Match {
				pcrsOK = false
				break
			}
		}
	}

	switch {
	case hasPcrlock && hasPin && pcrsOK:
		data.Tier = "HIGH"
	case hasPcrlock && hasPin && !pcrsOK:
		data.Tier = "WARNING"
	case hasPcrlock || hasToken:
		data.Tier = "MEDIUM"
	default:
		data.Tier = "LOW"
	}
}

func renderStatus(data *statusData, verbose bool) {
	var out strings.Builder
	out.WriteString("\n")
	out.WriteString(renderTier(data.Tier))
	out.WriteString("\n")

	for _, d := range data.LUKSDevices {
		out.WriteString(renderLUKS(d))
		out.WriteString("\n")
	}

	out.WriteString(renderTPM(data.TPM))
	out.WriteString("\n")

	if data.PCRLock != nil {
		out.WriteString(renderPCRLock(data.PCRLock))
		out.WriteString("\n")
	}

	fmt.Print(out.String())

	if verbose {
		renderVerboseExtras(data)
	}
}

func renderVerboseExtras(data *statusData) {
	for _, d := range data.LUKSDevices {
		if d.Token != nil {
			fmt.Printf("Token details for %s:\n", d.Path)
			fmt.Printf("  PIN: %v  PCRLock: %v  SRK: %v  Salt: %v\n",
				d.Token.HasPIN, d.Token.HasPCRLock, d.Token.HasSRK, d.Token.HasSalt)
			fmt.Printf("  NV Index: 0x%x  PCR Bank: %s\n", d.Token.NVIndex, d.Token.PCRBank)
		}
	}
	if data.PCRLock != nil {
		fmt.Println()
		for _, r := range data.PCRLock.PCRResults {
			label := "enforced"
			if !r.IsEnforced {
				label = "unbound"
			}
			m := "match"
			if !r.Match {
				m = errStyle.Render("MISMATCH")
			}
			fmt.Printf("  PCR %2d %-20s %s  %s\n", r.PCR, r.Name, m, dimStyle.Render(label))
			if r.Current != "" {
				fmt.Printf("    current: %s\n", r.Current)
			}
		}
	}
}

func renderTier(tier string) string {
	bar, label := "████░░░░░░░░  ", tierLow.Render("LOW")
	switch tier {
	case "HIGH":
		bar, label = "████████████  ", tierHigh.Render("HIGH")
	case "WARNING":
		bar, label = "████████░░░░  ", tierWarn.Render("WARNING — PCR mismatch")
	case "MEDIUM":
		bar, label = "████████░░░░  ", tierMed.Render("MEDIUM")
	}
	return fmt.Sprintf("  PROTECTION TIER: %s %s", bar, label)
}

func renderLUKS(d luksDeviceInfo) string {
	hdr := headerSty.Render(fmt.Sprintf("LUKS%d  %s", d.Version, d.Path))
	lines := []string{
		fmt.Sprintf(" UUID:  %s", fmt.Sprintf("%.12s...", d.UUID)),
		fmt.Sprintf(" Slots: %d active", d.Slots),
	}
	if d.Token != nil {
		t := d.Token
		flags := []string{okStyle.Render("systemd-tpm2")}
		if t.HasPIN {
			flags = append(flags, okStyle.Render("PIN"))
		}
		if t.HasPCRLock {
			flags = append(flags, okStyle.Render("pcrlock"))
		}
		if t.HasSRK {
			flags = append(flags, okStyle.Render("SRK"))
		}
		lines = append(lines, fmt.Sprintf(" Token: %s", strings.Join(flags, " ")))
		if t.NVIndex != 0 {
			lines = append(lines, fmt.Sprintf(" NV:    0x%x", t.NVIndex))
		}
	} else {
		lines = append(lines, fmt.Sprintf(" Token: %s", warnStyle.Render("passphrase only")))
	}

	return boxStyle.Render(hdr + "\n" + strings.Join(lines, "\n"))
}

func renderTPM(t tpmStatus) string {
	hdr := headerSty.Render("TPM 2.0")
	if !t.Present {
		return boxStyle.Render(hdr + "\n" + errStyle.Render(" Not available"))
	}
	lines := []string{
		fmt.Sprintf(" Device: %s %s", t.Device, okStyle.Render("available")),
	}
	if t.InLockout {
		lines = append(lines, errStyle.Render(
			fmt.Sprintf(" DA lockout: ACTIVE (%d/%d failures)", t.LockoutCounter, t.MaxAuthFail)))
	} else {
		rem := int64(t.MaxAuthFail) - int64(t.LockoutCounter)
		if rem < 0 {
			rem = 0
		}
		lines = append(lines,
			fmt.Sprintf(" DA lockout: %s (%d/%d remaining)", okStyle.Render("ok"), rem, t.MaxAuthFail))
	}
	return boxStyle.Render(hdr + "\n" + strings.Join(lines, "\n"))
}

func renderPCRLock(p *pcrlockInfo) string {
	hdr := headerSty.Render("BOOT INTEGRITY (PCRLock)")
	var lines []string

	lines = append(lines, fmt.Sprintf(" Policy: %s", p.PolicyPath))

	if p.NVIndex == 0 {
		lines = append(lines, dimStyle.Render(" NV:     none defined"))
	} else if p.NVOnTPM {
		lines = append(lines, fmt.Sprintf(" NV:     0x%x %s", p.NVIndex, okStyle.Render("present on TPM")))
	} else {
		lines = append(lines, fmt.Sprintf(" NV:     0x%x %s", p.NVIndex, errStyle.Render("NOT on TPM")))
		if p.TokenNVIndex != 0 && p.PolicyNVIndex != p.TokenNVIndex {
			lines = append(lines, dimStyle.Render(fmt.Sprintf("         policy claims 0x%x, token claims 0x%x", p.PolicyNVIndex, p.TokenNVIndex)))
		}
	}

	if len(p.PCRResults) == 0 && !p.PCR7InPolicy {
		lines = append(lines, dimStyle.Render("         no PCRs in policy"))
	} else {
		lines = append(lines, "")
		for _, r := range p.PCRResults {
			var prefix, suffix string
			if r.IsEnforced {
				if r.Match {
					prefix = okStyle.Render("  ✓")
					suffix = fmt.Sprintf("PCR %-2d  %-20s", r.PCR, r.Name)
				} else {
					prefix = errStyle.Render("  ✗")
					suffix = fmt.Sprintf("PCR %-2d  %-20s  %s", r.PCR, r.Name,
						errStyle.Render("MISMATCH — could prevent unlock"))
				}
			} else {
				prefix = dimStyle.Render("  —")
				suffix = fmt.Sprintf("PCR %-2d  %-20s  %s", r.PCR, r.Name,
					dimStyle.Render("unbound"))
			}
			lines = append(lines, fmt.Sprintf("%s %s", prefix, suffix))
		}

		if !p.PCR7InPolicy {
			lines = append(lines, "")
			lines = append(lines, warnStyle.Render("  ⚠ PCR 7  (secure-boot-policy) NOT in policy"))
			if p.PCR7Current != "" {
				current := fmt.Sprintf("%s", p.PCR7Current)
				if len(current) > 16 {
					current = current[:16] + "..."
				}
				lines = append(lines, dimStyle.Render(fmt.Sprintf("         current: %s  SB: %s", current, p.SecureBoot)))
			}
			lines = append(lines, dimStyle.Render(fmt.Sprintf("         Run: vanguard update-tpm-policy -u <uki> -l <luks-dev>")))
		}
	}

	return boxStyle.Render(hdr + "\n" + strings.Join(lines, "\n"))
}
