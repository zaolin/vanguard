package luks

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zaolin/vanguard/init/buildtags"
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
	Strategy     TPM2TokenStrategy
	Token        *TPM2Token
	PCRLockPath  string
	HasPCRLockNV bool
	HasPCRPolicy bool
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
	// First read the binary header to get the header length
	headerData, err := readDeviceRange(devicePath, 0, 32)
	if err != nil {
		return nil, err
	}

	// LUKS2 header format:
	//   Offset 0-5: "LUKS\xba\xbe" (6 bytes magic)
	//   Offset 6-7: version (big-endian uint16)
	//   Offset 8-15: hdr_len (big-endian uint64) - total header length including JSON area
	//   JSON area starts at offset 0x1000
	hdrLen := binary.BigEndian.Uint64(headerData[8:16])
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

	// The tpm2_pcrlock_nv field contains the NV public area (base64 encoded)
	// systemd v255+ stores this as raw bytes - the format varies
	if pcrlockNVData, ok := tokenJSON["tpm2_pcrlock_nv"].(string); ok {
		if token.PCRLockNV == 0 && pcrlockNVData != "" {
			nvData, err := base64.StdEncoding.DecodeString(pcrlockNVData)
			if err == nil && len(nvData) >= 4 {
				// Debug: show raw bytes
				debugLen := 16
				if debugLen > len(nvData) {
					debugLen = len(nvData)
				}
				buildtags.Debug("luks: NV data hex (first %d bytes): %x\n", debugLen, nvData[:debugLen])

				var nvIndex uint32

				// Try offset 0 first (direct NV index at start)
				if len(nvData) >= 4 {
					nvIndex = uint32(nvData[0])<<24 | uint32(nvData[1])<<16 | uint32(nvData[2])<<8 | uint32(nvData[3])
					buildtags.Debug("luks: NV index at offset 0: 0x%x\n", nvIndex)
					// Check if it's a valid NV index (should start with 0x01 for owner/platform hierarchy)
					if nvIndex&0xFF000000 == 0x01000000 {
						token.PCRLockNV = nvIndex
						buildtags.Debug("luks: parsed PCRLockNV: 0x%x\n", nvIndex)
					}
				}

				// Try TPM2B format: offset 2 (after 2-byte size)
				if token.PCRLockNV == 0 && len(nvData) >= 6 {
					nvIndex = uint32(nvData[2])<<24 | uint32(nvData[3])<<16 | uint32(nvData[4])<<8 | uint32(nvData[5])
					buildtags.Debug("luks: NV index at offset 2: 0x%x\n", nvIndex)
					if nvIndex&0xFF000000 == 0x01000000 {
						token.PCRLockNV = nvIndex
						buildtags.Debug("luks: parsed PCRLockNV (offset 2): 0x%x\n", nvIndex)
					}
				}

				// Try with authPolicy.size: calculate offset based on authPolicySize
				if token.PCRLockNV == 0 && len(nvData) >= 12 {
					authPolicySize := uint16(nvData[10])<<8 | uint16(nvData[11])
					buildtags.Debug("luks: authPolicy.size: %d\n", authPolicySize)
					offset := 2 + 2 + 2 + 4 + 2 + int(authPolicySize) // = 12 + authPolicySize
					if offset+4 <= len(nvData) {
						nvIndex = uint32(nvData[offset])<<24 | uint32(nvData[offset+1])<<16 | uint32(nvData[offset+2])<<8 | uint32(nvData[offset+3])
						buildtags.Debug("luks: NV index at offset %d: 0x%x\n", offset, nvIndex)
						if nvIndex&0xFF000000 == 0x01000000 {
							token.PCRLockNV = nvIndex
							buildtags.Debug("luks: parsed PCRLockNV (with authPolicy): 0x%x\n", nvIndex)
						}
					}
				}
			}
		}
	}

	// The tpm2_pcrlock_nv field contains the NV public area (base64 encoded)
	// systemd v255+ stores the TPM2B_NV_PUBLIC structure
	if pcrlockNVData, ok := tokenJSON["tpm2_pcrlock_nv"].(string); ok {
		if token.PCRLockNV == 0 && pcrlockNVData != "" {
			nvData, err := base64.StdEncoding.DecodeString(pcrlockNVData)
			if err == nil && len(nvData) >= 4 {
				// TPM2B_NV_PUBLIC structure:
				// - 2 bytes: size (total size of NVPublic)
				// - Then TPMS_NV_PUBLIC starts:
				//   - 2 bytes: infoAlg
				//   - 2 bytes: nameAlg (TPM2_ALG_SHA256 = 0x000B)
				//   - 4 bytes: attributes
				//   - 2 bytes: authPolicy.size
				//   - variable: authPolicy.data
				//   - 4 bytes: nvIndex
				//
				// For PCRLock, authPolicy.size is typically 0, so:
				// nvIndex is at offset: 2 + 2 + 4 + 2 = 10 bytes from TPMS_NV_PUBLIC start
				// = 12 bytes from the very beginning (after TPM2B size)

				// But looking at the hex: first 4 bytes are 0x018188a3
				// This is actually: 0x0188 (size) + 0x18a3 (start of infoAlg?)
				//
				// Actually the correct offset for NV index is:
				// After TPM2B size (2 bytes) + infoAlg(2) + nameAlg(2) + attributes(4) + authPolicySize(2)
				// = offset 12 from start

				if len(nvData) >= 16 {
					// NV index at offset 12 (after size + infoAlg + nameAlg + attributes + authPolicySize)
					nvIndex := uint32(nvData[12])<<24 | uint32(nvData[13])<<16 | uint32(nvData[14])<<8 | uint32(nvData[15])
					if nvIndex != 0 {
						token.PCRLockNV = nvIndex
						buildtags.Debug("luks: parsed PCRLockNV from NV public: 0x%x\n", nvIndex)
					}
				}
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
