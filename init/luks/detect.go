package luks

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zaolin/vanguard/init/buildtags"
	"github.com/zaolin/vanguard/internal/pcrlock"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// TPM2TokenStrategy represents the type of TPM2 token strategy.
type TPM2TokenStrategy int

const (
	StrategyUnknown TPM2TokenStrategy = iota
	StrategyPINOnly
	StrategyPCRPolicy
	StrategyPCRLock
)

// TokenDetectionResult contains the detection result for TPM2 token strategy.
type TokenDetectionResult struct {
	Strategy      TPM2TokenStrategy
	Token         *TPM2Token
	PCRLockPath   string
	PCRLockPolicy *intpm.PCRLockPolicy
	HasPCRLockNV  bool
	HasPCRPolicy  bool
}

// DetectTPM2TokenStrategy analyzes the LUKS2 header to determine the correct unseal strategy.
func DetectTPM2TokenStrategy(devicePath string) (*TokenDetectionResult, error) {
	result := &TokenDetectionResult{}

	buildtags.Debug("luks: DetectTPM2TokenStrategy: starting\n")

	vol, err := GetLUKS2Info(devicePath)
	if err != nil {
		buildtags.Debug("luks: DetectTPM2TokenStrategy: GetLUKS2Info failed: %v\n", err)
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	buildtags.Debug("luks: DetectTPM2TokenStrategy: header read OK, finding token\n")

	tokenJSON, err := findSystemdTPM2TokenInHeader(vol.BackingDevice)
	if err != nil {
		return nil, fmt.Errorf("failed to find TPM2 token: %w", err)
	}

	if tokenJSON == nil {
		return nil, fmt.Errorf("no systemd-tpm2 token found")
	}

	buildtags.Debug("luks: found systemd-tpm2 token in header\n")

	token, err := parseTokenJSON(tokenJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPM2 token: %w", err)
	}
	result.Token = token

	result.HasPCRPolicy = len(token.PCRs) > 0

	if len(token.PCRs) == 0 && !token.UsePCRLock && token.PCRLockNV == 0 {
		result.Strategy = StrategyPINOnly
		buildtags.Debug("luks: detected PIN-only strategy (no PCRs, no PCRLock)\n")
		return result, nil
	}

	pcrlockPath := detectPCRLockJSON()
	if pcrlockPath != "" {
		result.PCRLockPath = pcrlockPath
		result.Strategy = StrategyPCRLock
		buildtags.Debug("luks: detected PCRLock strategy (pcrlock.json found at %s)\n", pcrlockPath)

		policyData, err := os.ReadFile(pcrlockPath)
		if err == nil {
			policy, parseErr := intpm.ParsePCRLockJSON(policyData)
			if parseErr == nil {
				result.PCRLockPolicy = policy
				buildtags.Debug("luks: parsed pcrlock.json - NV=0x%x, %d PCR predictions\n",
					policy.NVIndex, len(policy.PCRPredictions))
			} else {
				buildtags.Debug("luks: failed to parse pcrlock.json: %v\n", parseErr)
			}
		}

		return result, nil
	}

	if token.UsePCRLock || token.PCRLockNV != 0 {
		result.Strategy = StrategyPCRLock
		buildtags.Debug("luks: detected PCRLock strategy (token has pcrlock flags)\n")
		return result, nil
	}

	result.Strategy = StrategyPCRPolicy
	buildtags.Debug("luks: detected PCR policy strategy (PCRs: %v)\n", token.PCRs)

	return result, nil
}

func findSystemdTPM2TokenInHeader(devicePath string) (map[string]interface{}, error) {
	// Validate magic, version, and hdr_len bounds via the shared reader —
	// a hostile hdr_len must never reach make([]byte, size) below.
	hdrLen, err := readValidatedHeaderLen(devicePath)
	if err != nil {
		return nil, err
	}
	jsonSize := hdrLen - 0x1000

	buildtags.Debug("luks: LUKS2 header length: %d, JSON size: %d\n", hdrLen, jsonSize)

	// Read the JSON area
	jsonData, err := readDeviceRange(devicePath, 0x1000, jsonSize)
	if err != nil {
		return nil, err
	}

	jsonEnd := findJSONEnd(jsonData)
	if jsonEnd <= 0 {
		return nil, fmt.Errorf("failed to find JSON boundary")
	}

	// Parse JSON directly (no config.json wrapper)
	var config struct {
		Tokens map[string]map[string]interface{} `json:"tokens"`
	}

	if err := json.Unmarshal(jsonData[:jsonEnd], &config); err != nil {
		return nil, err
	}

	for _, token := range config.Tokens {
		tokenType, ok := token["type"].(string)
		if !ok {
			continue
		}
		if tokenType == "systemd-tpm2" {
			return token, nil
		}
	}

	return nil, fmt.Errorf("no systemd-tpm2 token found")
}

func parseTokenJSON(tokenJSON map[string]interface{}) (*TPM2Token, error) {
	token := &TPM2Token{}

	if blob, ok := tokenJSON["tpm2-blob"].(string); ok {
		blobData, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return nil, fmt.Errorf("failed to decode blob: %w", err)
		}
		token.Blob = blobData
	}

	if pcrs, ok := tokenJSON["tpm2-pcrs"].([]interface{}); ok {
		token.PCRs = make([]int, len(pcrs))
		for i, p := range pcrs {
			switch v := p.(type) {
			case float64:
				token.PCRs[i] = int(v)
			case int:
				token.PCRs[i] = v
			}
		}
	}

	if pcrBank, ok := tokenJSON["tpm2-pcr-bank"].(string); ok {
		token.PCRBank = pcrBank
	}

	if pin, ok := tokenJSON["tpm2-pin"].(bool); ok {
		token.NeedsPIN = pin
	}

	if salt, ok := tokenJSON["tpm2-salt"].(string); ok {
		saltData, err := base64.StdEncoding.DecodeString(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode salt: %w", err)
		}
		token.Salt = saltData
	}

	if saltAlt, ok := tokenJSON["tpm2_salt"].(string); ok {
		if len(token.Salt) == 0 {
			saltData, err := base64.StdEncoding.DecodeString(saltAlt)
			if err != nil {
				return nil, fmt.Errorf("failed to decode salt alt: %w", err)
			}
			token.Salt = saltData
		}
	}

	if policyHash, ok := tokenJSON["tpm2-policy-hash"].(string); ok {
		hashData, err := hex.DecodeString(policyHash)
		if err != nil {
			return nil, fmt.Errorf("failed to decode policy hash: %w", err)
		}
		token.PolicyHash = hashData
	}

	if pcrlock, ok := tokenJSON["tpm2-pcrlock"].(bool); ok {
		token.UsePCRLock = pcrlock
	}

	if pcrlockAlt, ok := tokenJSON["tpm2_pcrlock"].(bool); ok {
		token.UsePCRLock = token.UsePCRLock || pcrlockAlt
	}

	if pcrlockNV, ok := tokenJSON["tpm2-pcrlock-nv"].(float64); ok {
		token.PCRLockNV = uint32(pcrlockNV)
	}

	// Parse the tpm2_pcrlock_nv field. This field contains the base64-encoded
	// TPM2B_NV_PUBLIC structure from systemd v255+. The shared validated
	// parser (pcrlock.ParseNVIndexFromBlob) handles both the spec-compliant
	// offset-2 layout and the legacy offset-0 layout, with a pcrlock range
	// check — identical to the unseal path in token.go.
	if pcrlockNVData, ok := tokenJSON["tpm2_pcrlock_nv"].(string); ok {
		if token.PCRLockNV == 0 && pcrlockNVData != "" {
			if idx, err := pcrlock.ParseNVIndexFromBlob(pcrlockNVData); err == nil {
				token.PCRLockNV = idx
				buildtags.Debug("luks: parsed PCRLockNV: 0x%x\n", token.PCRLockNV)
			} else {
				buildtags.Debug("luks: NV index parse failed: %v\n", err)
			}
		}
	}

	if primaryAlg, ok := tokenJSON["tpm2-primary-alg"].(string); ok {
		token.PrimaryAlg = primaryAlg
	}

	if srkHandle, ok := tokenJSON["tpm2-srk"].(string); ok {
		if srkHandle != "" {
			var err error
			token.SRKHandle, err = parseHexUint32(srkHandle)
			if err != nil {
				buildtags.Debug("luks: warning: failed to parse SRK handle: %v\n", err)
			}
		}
	}

	if srkDataAlt, ok := tokenJSON["tpm2_srk"].(string); ok {
		if token.SRKHandle == 0 && srkDataAlt != "" {
			buildtags.Debug("luks: note: SRK data present (systemd v255+), using transient SRK\n")
		}
	}

	return token, nil
}

func detectPCRLockJSON() string {
	searchPaths := []string{
		"/run/systemd/pcrlock.json",
		"/var/lib/systemd/pcrlock.json",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func parseHexUint32(s string) (uint32, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("invalid hex length")
	}
	return uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]), nil
}
