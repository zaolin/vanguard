package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/zaolin/vanguard/internal/fstab"
	"github.com/zaolin/vanguard/internal/luks"
	"github.com/zaolin/vanguard/internal/pcrlock"
	"github.com/zaolin/vanguard/internal/tpm"
)

type statusData struct {
	Tier             string                `json:"tier"`
	TPM              tpmStatus             `json:"tpm"`
	LUKSDevices      []luksDeviceInfo      `json:"luks"`
	PCRLock          *pcrlockInfo          `json:"pcrlock,omitempty"`
	HeaderBinding    *headerBindingInfo    `json:"headerBinding,omitempty"`
	SecureBoot       *secureBootInfo       `json:"secureBoot,omitempty"`
	HardwareSecurity *hardwareSecurityInfo `json:"hardwareSecurity,omitempty"`
	Sbctl            *sbctlInfo            `json:"sbctl,omitempty"`
	Recovery         *recoveryInfo         `json:"recovery,omitempty"`
	Fwupd            *fwupdInfo            `json:"fwupd,omitempty"`
	HSTI             *hstiInfo             `json:"hsti,omitempty"`
	ThreatModel      []threatVector        `json:"threatModel,omitempty"`
}

// headerBindingInfo carries the LUKS header PCR 11 binding check result.
// See internal/pcrlock.VerifyLUKSHeaderBinding for semantics: the on-disk
// LUKS2 header digest is compared against the enrollment-time component
// digests, not against the live PCR 11 (which legitimately includes
// post-unlock systemd extensions).
type headerBindingInfo struct {
	Bound           bool     `json:"bound"`
	Match           bool     `json:"match"`
	Detail          string   `json:"detail"`
	OnDiskDigest    string   `json:"onDiskDigest,omitempty"`
	EnrolledDigests []string `json:"enrolledDigests,omitempty"`
	Device          string   `json:"device,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// PCR11ForStatus is the PCR index whose live value diverges from the policy
// prediction by design after unlock (kernel-boot PCR with systemd phases).
const PCR11ForStatus = 11

type tpmStatus struct {
	Present        bool   `json:"present"`
	Device         string `json:"device,omitempty"`
	InLockout      bool   `json:"inLockout"`
	LockoutCounter uint64 `json:"lockoutCounter"`
	MaxAuthFail    uint64 `json:"maxAuthFail"`
	LockoutError   string `json:"lockoutError,omitempty"`

	// Identity and functional health, filled when the TPM responds.
	Identity       *tpmIdentityInfo `json:"identity,omitempty"`
	IdentityError  string           `json:"identityError,omitempty"`
	Banks          []string         `json:"banks,omitempty"`
	BanksError     string           `json:"banksError,omitempty"`
	RandomOK       *bool            `json:"randomOk,omitempty"`
	RandomError    string           `json:"randomError,omitempty"`
	RoundtripOK    *bool            `json:"roundtripOk,omitempty"`
	RoundtripError string           `json:"roundtripError,omitempty"`
	// RoundtripSkipped is set when no roundtrip was attempted because the
	// lockout state is unknown, the TPM is locked out, or an owner/lockout
	// auth is configured.
	RoundtripSkipped string `json:"roundtripSkipped,omitempty"`
	// AuthBlocked explains why no new authorizations may be attempted with an
	// empty auth value ("" = they are safe).
	AuthBlocked string `json:"authBlocked,omitempty"`
	// RoundtripClass distinguishes "could not verify" (authorization or
	// transport problem) from a genuine seal/unseal failure.
	RoundtripClass string `json:"roundtripClass,omitempty"`
}

// tpmIdentityInfo is the TPM vendor/firmware identification shown in status.
type tpmIdentityInfo struct {
	Manufacturer string `json:"manufacturer"`
	VendorString string `json:"vendorString"`
	Firmware     string `json:"firmware"`
	Family       string `json:"family"`
	FirmwareTPM  bool   `json:"firmwareTpm"`
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
	PrimaryAlg string `json:"primaryAlg,omitempty"`
}

type recoveryInfo struct {
	Enabled   bool   `json:"enabled"`
	Counter   uint64 `json:"counter,omitempty"`
	FailCount uint32 `json:"failCount,omitempty"`
	Locked    bool   `json:"locked,omitempty"`
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
	PolicyPath    string `json:"policyPath"`
	PolicyNVIndex uint32 `json:"policyNvIndex"`
	TokenNVIndex  uint32 `json:"tokenNvIndex"`
	NVOnTPM       bool   `json:"nvOnTpm"`
	// NVOnTPMUnknown is set when the NV state could not be read at all.
	NVOnTPMUnknown bool        `json:"nvOnTpmUnknown,omitempty"`
	NVIndex        uint32      `json:"nvIndex"`
	PCRResults     []pcrStatus `json:"pcrResults"`
	EnforcedPCRs   []int       `json:"enforcedPcrs"`
	UnboundPCRs    []int       `json:"unboundPcrs"`
	PCR7Current    string      `json:"pcr7Current,omitempty"`
	PCR7InPolicy   bool        `json:"pcr7InPolicy"`
	SecureBoot     string      `json:"secureBoot"`
}

type pcrStatus struct {
	PCR   int    `json:"pcr"`
	Name  string `json:"name"`
	Match bool   `json:"match"`
	// Unknown marks a PCR whose live value could not be read. It must not be
	// rendered or counted as a mismatch.
	Unknown    bool   `json:"unknown,omitempty"`
	IsEnforced bool   `json:"isEnforced"`
	Current    string `json:"current,omitempty"`
}

type tokenPayloadJSON struct {
	Pin          bool   `json:"tpm2-pin"`
	PCRLock      bool   `json:"tpm2-pcrlock"`
	PCRLockAlt   bool   `json:"tpm2_pcrlock"`
	PCRBank      string `json:"tpm2-pcr-bank"`
	PrimaryAlg   string `json:"tpm2-primary-alg"`
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

	// Build the threat model once — computeTier derives the tier from it.
	data.ThreatModel = buildThreatModel(&data)
	computeTier(&data)

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
	info := &recoveryInfo{
		Enabled: client.RecoveryNVExists(tpm.DefaultRecoverySeedNVIndex),
	}
	// Surface the HOTP counter/fail state (owner-auth read; non-fatal).
	if counter, failCount, err := client.ReadRecoveryState(); err == nil {
		info.Counter = counter
		info.FailCount = failCount
		info.Locked = failCount >= recoveryMaxFailCount
	}
	return info
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
		// A configured swtpm/UDS socket is also a TPM: checking only the
		// device nodes would report a healthy simulator as absent.
		if sock := os.Getenv("VANGUARD_TPM_SOCKET"); sock != "" {
			if _, err := os.Stat(sock); err == nil {
				data.TPM.Present = true
				data.TPM.Device = sock
			}
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

	// Vendor/firmware identification and functional health. Each check is
	// independent: a failure is reported, never fatal to the status run.
	if id, err := client.ReadIdentity(); err != nil {
		data.TPM.IdentityError = err.Error()
	} else {
		data.TPM.Identity = &tpmIdentityInfo{
			Manufacturer: id.ManufacturerName,
			VendorString: id.VendorString,
			Firmware:     id.FirmwareVersionString(),
			Family:       string(id.Family()),
			FirmwareTPM:  id.IsFirmwareTPM(),
		}
	}

	if banks, err := client.PCRBanks(); err != nil {
		data.TPM.BanksError = err.Error()
	} else {
		data.TPM.Banks = banks
	}

	if err := client.GetRandomSmoke(); err != nil {
		data.TPM.RandomError = err.Error()
		if errors.Is(err, tpm.ErrRandomIdentical) {
			data.TPM.RandomOK = boolPtr(false)
		}
		// Any other error means the check could not run at all: leave
		// RandomOK nil so the report says "unverified", not "broken".
	} else {
		data.TPM.RandomOK = boolPtr(true)
	}

	// Decide whether new authorizations with an empty auth value are safe.
	// Owner/lockout auth is read from TPM_PT_PERMANENT — a read-only query,
	// so no failed authorization is needed to learn it. Probing it would
	// risk consuming a dictionary-attack attempt on a healthy TPM.
	var flagsErr error
	var flags tpm.PermanentFlags
	if data.TPM.LockoutError == "" && !data.TPM.InLockout {
		flags, flagsErr = client.ReadPermanentFlags()
	}
	data.TPM.AuthBlocked = authBlockReason(data.TPM.LockoutError, data.TPM.InLockout, flags, flagsErr)
	data.TPM.RoundtripSkipped = data.TPM.AuthBlocked

	if data.TPM.AuthBlocked == "" {
		if err := sealRoundtrip(client); err != nil {
			data.TPM.RoundtripOK = boolPtr(false)
			data.TPM.RoundtripError = err.Error()
			data.TPM.RoundtripClass = roundtripClassFor(err)
		} else {
			data.TPM.RoundtripOK = boolPtr(true)
		}
	}
}

// sealRoundtrip performs the seal/unseal health check. It is a package
// variable so the production classification of its result can be tested with
// an injected failure instead of only through the helper in isolation.
var sealRoundtrip = func(client *tpm.Client) error {
	return client.SealUnsealRoundtrip()
}

// boolPtr returns a pointer to b, used for tri-state health results
// (nil = the check was not attempted).
func boolPtr(b bool) *bool { return &b }

// roundtripClassFor classifies a seal/unseal roundtrip error: "failed" for a
// genuine failure (a data mismatch or a TPM error response), "unverified" for
// an authorization requirement or a transport problem, where the check could
// not run at all and nothing about the TPM is proven.
func roundtripClassFor(err error) string {
	if errors.Is(err, tpm.ErrRoundtripMismatch) {
		// A data mismatch is a genuine seal/unseal failure even though it is
		// detected locally rather than by the TPM.
		return "failed"
	}
	if tpm.IsAuthorizationFailure(err) {
		return "unverified"
	}
	if !tpm.IsTPMResponseError(err) {
		return "unverified"
	}
	return "failed"
}

// authBlockReason decides whether new TPM operations with an empty auth value
// may be attempted. It fails SAFE: any state in which an authorization could
// fail (unknown lockout, active lockout, configured owner/lockout auth, or an
// unreadable permanent-flags property) blocks the operation. Otherwise a
// routine status run could consume a dictionary-attack attempt on a healthy
// TPM and eventually lock it out.
func authBlockReason(lockoutErr string, inLockout bool, flags tpm.PermanentFlags, flagsErr error) string {
	switch {
	case lockoutErr != "":
		return "the lockout state could not be read"
	case inLockout:
		return "the TPM is in dictionary-attack lockout"
	case flagsErr != nil:
		return "TPM_PT_PERMANENT could not be read — authorization requirements are unknown"
	case flags&tpm.PermanentOwnerAuthSet != 0 || flags&tpm.PermanentLockoutAuthSet != 0:
		return "owner/lockout auth is set — no empty-auth operations are attempted"
	default:
		return ""
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

		tokens, tokenErr := dev.Tokens()
		dev.Close()
		if tokenErr != nil {
			// Unreadable token data — device will show as passphrase-only.
			fmt.Fprintf(os.Stderr, "vanguard: warning: failed to read tokens from %s: %v\n", info.Path, tokenErr)
		}

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
		// Shared validated parser (offset 2 spec-compliant, offset 0 legacy,
		// pcrlock range check) — same logic as the boot path in init/luks.
		if idx, err := pcrlock.ParseNVIndexFromBlob(raw.PCRLockNVAlt); err == nil {
			td.NVIndex = idx
		}
	}
	td.HasSalt = raw.Salt != "" || raw.SaltAlt != ""
	td.HasSRK = raw.SRK != 0 || raw.SRKAlt != ""

	td.PCRBank = raw.PCRBank
	if td.PCRBank == "" {
		td.PCRBank = "sha256"
	}
	td.PrimaryAlg = raw.PrimaryAlg

	return td
}

// bootedUKIPathFn and policyMatchingTokenNVFn are package variables so
// the policy-selection logic can be tested without a real EFI/boot setup.
var (
	bootedUKIPathFn         = bootedUKIPath
	policyMatchingTokenNVFn = policyMatchingTokenNV
)

// installedPolicies returns the pcrlock policies installed below the EFI
// System Partition, sorted for stable results.
//
// The ESP is not necessarily mounted at /boot (some systems use /efi), so
// the mount point is looked up rather than hardcoded. It is a variable so
// tests can point the lookup at a temporary directory.
var installedPolicies = func() []string {
	matches, err := filepath.Glob(filepath.Join(espMountPoint(), "EFI", "*", "*.pcrlock.json"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

// standardPolicyPaths lists the system locations a pcrlock policy may live
// in, in preference order. It is a variable so tests can point the lookup at
// a temporary directory.
var standardPolicyPaths = func() []string {
	return []string{
		"/var/lib/systemd/pcrlock.json",
		filepath.Join(espMountPoint(), "pcrlock.json"),
		"/run/systemd/pcrlock.json",
	}
}

// policyPathForUKI derives the pcrlock policy path for a UKI: the UKI
// path without its .efi suffix plus ".pcrlock.json".
//
// The .efi stripping is case-insensitive (kernel.efi, kernel.EFI,
// BOOTX64.EFI), so the policy lookup and the policy generation always
// agree on the file name.
func policyPathForUKI(ukiPath string) string {
	base := ukiPath
	if strings.HasSuffix(strings.ToLower(base), ".efi") {
		base = base[:len(base)-4]
	}
	return base + ".pcrlock.json"
}

// findPCRLockPolicy locates the pcrlock policy that actually applies to
// this system.
//
// Picking the first glob match is wrong when several UKIs exist (an old
// and a new kernel.efi, for example): the status output would then report
// the NV index of a policy that is not in use, showing a bogus "Token NV
// mismatch". The policy is therefore selected by:
//
//  1. The booted UKI (LoaderImageIdentifier) — the same source the initrd
//     uses to find the policy at boot.
//  2. The policy whose NV index matches the LUKS device's token.
//  3. The standard system locations.
//  4. Otherwise, a single unambiguous glob match.
func findPCRLockPolicy() string {
	// 1. The booted UKI's policy.
	if uki := bootedUKIPathFn(); uki != "" {
		candidate := policyPathForUKI(uki)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 2. The policy matching the token's NV index.
	if policy := policyMatchingTokenNVFn(); policy != "" {
		// Only accept a policy that actually exists — a stale match would
		// make the status output describe a policy that is not in force.
		if _, err := os.Stat(policy); err == nil {
			return policy
		}
	}

	// 3. Standard system locations.
	for _, p := range standardPolicyPaths() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// 4. A single unambiguous policy installed below the ESP.
	//
	// With several candidates the active one is unknown: picking the first
	// would report (and NV-verify against) a policy that may not be in
	// force, producing a false "NV was rewritten" diagnosis. Report no
	// policy instead of guessing.
	matches := installedPolicies()
	if len(matches) != 1 {
		return ""
	}
	return matches[0]
}

// bootedUKIPath returns the path of the UKI that was booted, as recorded in
// the LoaderImageIdentifier EFI variable. Empty when unavailable (e.g. a
// BIOS boot or a container).
func bootedUKIPath() string {
	efiVarPath := "/sys/firmware/efi/efivars/LoaderImageIdentifier-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
	data, err := os.ReadFile(efiVarPath)
	if err != nil {
		return ""
	}
	return decodeLoaderImageIdentifier(data)
}

// decodeLoaderImageIdentifier decodes the LoaderImageIdentifier EFI
// variable: a 4-byte attribute header followed by a UTF-16LE string. The
// result is the absolute path of the booted UKI (e.g.
// /boot/EFI/Gentoo/kernel.efi).
func decodeLoaderImageIdentifier(data []byte) string {
	if len(data) < 6 {
		return ""
	}
	// 4-byte attribute header, then a UTF-16LE string.
	runes := make([]rune, 0, 32)
	for i := 4; i+1 < len(data); i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	path := strings.ReplaceAll(string(runes), "\\", "/")
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return espMountPoint() + path
}

// espMountPoint returns the mount point of the EFI System Partition. The
// ESP is not always mounted at /boot (some systems use /efi), so the
// mount point is read from /etc/fstab; /boot is the fallback.
func espMountPoint() string {
	entries, err := fstab.Parse("/etc/fstab")
	if err != nil {
		return "/boot"
	}
	for _, e := range entries {
		if e.FSType == "vfat" && strings.Contains(e.Options, "boot=esp") {
			if e.Mountpoint != "" {
				return e.Mountpoint
			}
		}
	}
	return "/boot"
}

// policyMatchingTokenNV returns the policy file whose nvIndex equals the
// NV index pinned by the LUKS device's systemd-tpm2 token — i.e. the
// policy that is actually in force for the encrypted volume.
func policyMatchingTokenNV() string {
	devices, err := luks.Detect()
	if err != nil {
		return ""
	}
	var tokenNV int
	for _, dev := range devices {
		tok, err := pcrlock.GetLUKSTPMToken(dev.Path)
		if err != nil || tok.NVIndex == 0 {
			continue
		}
		tokenNV = tok.NVIndex
		break
	}
	if tokenNV == 0 {
		return ""
	}

	var match string
	for _, m := range installedPolicies() {
		policy, err := pcrlock.ParsePolicy(m)
		if err != nil {
			continue
		}
		if policy.NVIndex != tokenNV {
			continue
		}
		if match != "" {
			// Several policies share the token's NV index: the active one
			// is unknown, so do not pick one arbitrarily.
			return ""
		}
		match = m
	}
	return match
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

	// LUKS header binding check: compare the on-disk header digest against
	// the enrollment-time component digests. Checked per device with a TPM2
	// token; the first device that yields a binding result wins (typically
	// a single LUKS device).
	data.HeaderBinding = collectHeaderBinding(data.LUKSDevices)

	if info.NVIndex != 0 {
		exists, known := tpmNVExists(info.NVIndex)
		info.NVOnTPM = exists
		info.NVOnTPMUnknown = !known
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
		var rawValues []string
		for _, pv := range policy.PCRValues {
			if pv.PCR == pcr {
				rawValues = pv.Values
				for _, v := range pv.Values {
					b, err := hexDecode(v)
					if err == nil {
						allowed = append(allowed, b)
					}
				}
				break
			}
		}

		// Shared enforcement semantics with vanguard verify: enforced when
		// at least one allowed value is not the all-zero digest.
		isEnforced := pcrlock.IsEnforcedValues(rawValues)
		if isEnforced {
			info.EnforcedPCRs = append(info.EnforcedPCRs, pcr)
		} else {
			info.UnboundPCRs = append(info.UnboundPCRs, pcr)
		}

		match := !isEnforced
		unknown := false
		if current, ok := currentPCRs[pcr]; ok {
			for _, a := range allowed {
				if bytesEqual(current, a) {
					match = true
					break
				}
			}
		} else if isEnforced {
			if currentPCRs == nil {
				// The TPM could not be read at all: the PCR state is
				// unknown, not a mismatch.
				unknown = true
			} else {
				match = false
			}
		}

		var currentHex string
		if current, ok := currentPCRs[pcr]; ok {
			currentHex = hexEncode(current)
		}

		info.PCRResults = append(info.PCRResults, pcrStatus{
			PCR:        pcr,
			Name:       name,
			Match:      match,
			Unknown:    unknown,
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

// tpmNVExists reports whether the index is defined, and whether the NV state
// could be read at all. A failed read is unknown, not "missing".
func tpmNVExists(index uint32) (exists, known bool) {
	client := tpm.New()
	// Probe the index directly: a list-based check would silently treat an
	// omitted index (a per-index read failure) as "not present".
	if _, err := client.NVReadPublic(index); err != nil {
		if tpm.IsNVIndexMissing(err) {
			return false, true // definitively not defined
		}
		return false, false // transient or other failure: unknown
	}
	return true, true
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
	if !client.WaitForDevice(2 * time.Second) {
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
	// No bank produced a value: the TPM state is unavailable, not "all PCRs
	// mismatch". Report nil so callers can tell it apart from valid data.
	if len(result) == 0 {
		return nil
	}
	return result
}

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// collectHeaderBinding runs the LUKS header digest check for each LUKS
// device and returns the first binding result that indicates an enrolled
// (bound) header component. Devices without a TPM2 token are skipped.
// Per-device errors are remembered and only surfaced when NO device yielded
// a real binding — an error on one device must never mask a tampered header
// on another. Returns nil when there is nothing to report.
func collectHeaderBinding(devices []luksDeviceInfo) *headerBindingInfo {
	var firstErr *headerBindingInfo
	for _, d := range devices {
		if d.Token == nil {
			continue
		}
		res, err := pcrlock.VerifyLUKSHeaderBinding(d.Path)
		if err != nil {
			// Remember the error and keep scanning other devices.
			if firstErr == nil {
				firstErr = &headerBindingInfo{
					Device: d.Path,
					Error:  err.Error(),
				}
			}
			continue
		}
		if !res.Bound {
			continue
		}
		return &headerBindingInfo{
			Bound:           res.Bound,
			Match:           res.Match,
			Detail:          res.Detail,
			OnDiskDigest:    res.OnDiskDigest,
			EnrolledDigests: res.EnrolledDigests,
			Device:          d.Path,
		}
	}
	return firstErr
}

// pcr11Result returns the PCR 11 entry from the policy PCR results.
func pcr11Result(results []pcrStatus) (pcrStatus, bool) {
	for _, r := range results {
		if r.PCR == PCR11ForStatus {
			return r, true
		}
	}
	return pcrStatus{}, false
}

// pcr11Enforced reports whether PCR 11 appears as enforced in the policy.
func pcr11Enforced(results []pcrStatus) bool {
	r, ok := pcr11Result(results)
	return ok && r.IsEnforced
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

func computeTier(data *statusData) {
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
	vectors = append(vectors, buildTPMVulnerabilityVector(data))
	vectors = append(vectors, buildTPMHealthVector(data))
	vectors = append(vectors, buildDMAAttackVector(data))
	vectors = append(vectors, buildKernelRuntimeVector(data))
	vectors = append(vectors, buildColdBootVector(data))
	vectors = append(vectors, buildPlatformExposureVector(data))
	vectors = append(vectors, buildBruteForceVector(data))
	vectors = append(vectors, buildPhysicalDebugVector(data))
	vectors = append(vectors, buildFirmwareTamperingVector(data))
	vectors = append(vectors, buildSMMAttackVector(data))
	vectors = append(vectors, buildBootParamVector(data))

	for i := range vectors {
		vectors[i].Status = vectorStatus(&vectors[i])
		vectors[i].Collapsed = vectorIsCollapsed(&vectors[i])
	}

	return vectors
}

func vectorIsCollapsed(v *threatVector) bool {
	for _, m := range v.Mitigations {
		// "advisory" is context (a vendor CVE, a simulator note), not a
		// verified defect — like "info" it must not mark the vector as
		// problematic or drag the overall protection tier down.
		if m.Status != "ok" && m.Status != "info" && m.Status != "advisory" {
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
		pcr7Unknown := false
		for _, r := range data.PCRLock.PCRResults {
			if r.PCR == 7 {
				pcr7Bound = r.IsEnforced
				pcr7Match = r.Match
				pcr7Unknown = r.Unknown
				break
			}
		}
		switch {
		case !pcr7Bound:
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 7",
				Status: "warning",
				Detail: "not in policy — Secure Boot state not measured",
				Fix:    "Run: vanguard update -u <uki> -l <luks-dev>",
			})
		case pcr7Unknown:
			// An unreadable PCR is not a Secure Boot change.
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 7",
				Status: "info",
				Detail: "could not be read — Secure Boot state unverified",
			})
		case !pcr7Match:
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 7",
				Status: "critical",
				Detail: "MISMATCH — Secure Boot state changed since enrollment",
			})
		default:
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
	unknownPCRs := []string{}
	// PCR 11's live value legitimately diverges from the policy in a booted
	// system: the policy predicts the at-unseal-time value (sd-stub + LUKS
	// header), and systemd extends PCR 11 further after unlock. The header
	// binding itself is checked separately via the on-disk header digest —
	// exclude PCR 11 from the live-match critical trigger.
	for _, r := range data.PCRLock.PCRResults {
		if !r.IsEnforced {
			continue
		}
		if r.Unknown {
			// An unreadable PCR — including PCR 11 — counts as enforced but
			// is reported as unknown, never as a live mismatch.
			enforcedCount++
			unknownPCRs = append(unknownPCRs, fmt.Sprintf("PCR %d (%s)", r.PCR, r.Name))
			continue
		}
		if r.PCR == PCR11ForStatus && data.HeaderBinding != nil {
			// Handled by the dedicated LUKS header binding check below.
			continue
		}
		enforcedCount++
		if r.Match {
			matchCount++
		} else {
			mismatchPCRs = append(mismatchPCRs, fmt.Sprintf("PCR %d (%s)", r.PCR, r.Name))
		}
	}
	// Fall back to including PCR 11 when no digest check data is available
	// (older policy on disk, non-LUKS device, or check errored).
	if data.HeaderBinding == nil {
		for _, r := range data.PCRLock.PCRResults {
			if r.IsEnforced && r.PCR == PCR11ForStatus && !r.Unknown {
				enforcedCount++
				if r.Match {
					matchCount++
				} else {
					mismatchPCRs = append(mismatchPCRs, fmt.Sprintf("PCR %d (%s)", r.PCR, r.Name))
				}
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
	} else if len(unknownPCRs) == 0 {
		// "All match" is only claimed when nothing was unreadable.
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR binding",
			Status: "ok",
			Detail: fmt.Sprintf("%d PCRs bound, all match", matchCount),
		})
	}

	if len(unknownPCRs) > 0 {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR binding",
			Status: "info",
			Detail: fmt.Sprintf("%d PCR(s) could not be read: %s", len(unknownPCRs), strings.Join(unknownPCRs, ", ")),
		})
	}

	// NV index on TPM
	if data.PCRLock.NVIndex != 0 {
		if data.PCRLock.NVOnTPMUnknown {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock NV index",
				Status: "info",
				Detail: fmt.Sprintf("0x%x could not be verified (TPM read failed)", data.PCRLock.NVIndex),
			})
		} else if data.PCRLock.NVOnTPM {
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

	// PCR 11 (LUKS header binding)
	// Detects offline LUKS header tampering: adding a backdoor keyslot,
	// weakening KDF, or changing the cipher. The security property is
	// "the on-disk header is unchanged since enrollment", checked by
	// comparing the on-disk header digest against the enrollment-time
	// component digests (755-vanguard-luks-header.pcrlock.d).
	//
	// The live PCR 11 value is NOT compared against the policy here: the
	// policy predicts the at-unseal-time value, and systemd extends PCR 11
	// further after unlock (850-sysinit, 900-ready), so a live comparison
	// always mismatches in a booted system and is not a security signal.
	if data.HeaderBinding != nil && data.HeaderBinding.Bound {
		if data.HeaderBinding.Match {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 11 (LUKS header)",
				Status: "ok",
				Detail: "bound — LUKS header unchanged since enrollment",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 11 (LUKS header)",
				Status: "critical",
				Detail: "MISMATCH — LUKS header changed since enrollment",
				Fix:    "Verify the change was intentional (cryptsetup reenroll/keyslot change); then run: vanguard update -u <uki> -l <luks-dev>",
			})
		}
	} else if data.HeaderBinding != nil && !data.HeaderBinding.Bound && pcr11Enforced(data.PCRLock.PCRResults) {
		// PCR 11 is in the policy but the header binding check couldn't
		// verify the digest (e.g. non-LUKS device passed). Surface the live
		// comparison result as informational instead of critical.
		if r, ok := pcr11Result(data.PCRLock.PCRResults); ok && r.Match {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 11 (LUKS header)",
				Status: "ok",
				Detail: "bound — live PCR 11 matches policy",
			})
		} else {
			v.Mitigations = append(v.Mitigations, mitigation{
				Name:   "PCRLock PCR 11 (LUKS header)",
				Status: "warning",
				Detail: "pcrlock-enforced — live PCR 11 does not match policy (expected after boot; header digest unverifiable)",
			})
		}
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "PCRLock PCR 11 (LUKS header)",
			Status: "info",
			Detail: "not bound — LUKS header tampering not detected (use -l <luks-dev> with vanguard update)",
		})
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
	if data.TPM.LockoutError != "" {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "Dictionary attack lockout",
			Status: "info",
			Detail: "could not be read: " + data.TPM.LockoutError,
		})
	} else if data.TPM.InLockout {
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
			Name:   "HOTP fallback",
			Status: "ok",
			Detail: "recovery code enrolled",
		})
	} else {
		v.Mitigations = append(v.Mitigations, mitigation{
			Name:   "HOTP fallback",
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
	// Always expand — show all mitigations (Collapsed is used only in JSON)

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
		switch {
		case r.Unknown:
			matchStr = warnStyle.Render("unknown")
		case r.Match:
			matchStr = okStyle.Render("match")
		default:
			matchStr = errStyle.Render("MISMATCH")
		}

		// PCR 11 special case: the policy predicts the at-unseal-time value,
		// systemd extends PCR 11 after unlock, so the live value diverges by
		// design. Show the on-disk header digest binding instead — that is
		// the actual security property.
		if r.PCR == PCR11ForStatus && r.IsEnforced && data.HeaderBinding != nil {
			out.WriteString(fmt.Sprintf("    PCR %-2d %-20s %s  %s\n", r.PCR, r.Name,
				renderHeaderBindingMatch(data.HeaderBinding), dimStyle.Render(label)))
			if data.HeaderBinding.OnDiskDigest != "" {
				out.WriteString(fmt.Sprintf("      header:   %s\n", data.HeaderBinding.OnDiskDigest))
			}
			for _, ed := range data.HeaderBinding.EnrolledDigests {
				out.WriteString(fmt.Sprintf("      enrolled: %s\n", ed))
			}
			out.WriteString(fmt.Sprintf("      %s\n", dimStyle.Render(headerBindingDetail(data.HeaderBinding))))
			if r.Current != "" {
				out.WriteString(fmt.Sprintf("      live:     %s %s\n", r.Current, dimStyle.Render("(includes post-unlock systemd measurements)")))
			}
			continue
		}

		out.WriteString(fmt.Sprintf("    PCR %-2d %-20s %s  %s\n", r.PCR, r.Name, matchStr, dimStyle.Render(label)))
		if r.Current != "" {
			out.WriteString(fmt.Sprintf("      current: %s\n", r.Current))
		}
	}
	return out.String()
}

// renderHeaderBindingMatch renders the header binding result for the PCR
// DETAILS table.
func renderHeaderBindingMatch(info *headerBindingInfo) string {
	if info.Error != "" {
		return dimStyle.Render("unverifiable")
	}
	if info.Match {
		return okStyle.Render("match")
	}
	return errStyle.Render("MISMATCH")
}

// headerBindingDetail returns the explanation line for the PCR DETAILS
// table: the check's Detail, or the error text when the check itself
// failed (so the failure is diagnosable instead of a blank line).
func headerBindingDetail(info *headerBindingInfo) string {
	if info.Detail != "" {
		return info.Detail
	}
	if info.Error != "" {
		return "header digest check failed: " + info.Error
	}
	return ""
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
