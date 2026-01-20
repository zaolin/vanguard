package pcrlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// InjectPCR8 reads the 800-luks-header.pcrlock file and injects its PCR 8 measurement
// into the final policy JSON if it's missing. This bypasses systemd-pcrlock's
// requirement for the event log to contain the measurement (which it won't for
// our manual extensions).
func InjectPCR8(policyPath string) error {
	// 1. Read the policy JSON
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// 2. Check if PCR 8 is already present
	pcrValues, ok := policy["pcrValues"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid policy format: missing pcrValues")
	}

	for _, p := range pcrValues {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if pcr, ok := pMap["pcr"].(float64); ok && int(pcr) == 8 {
			// PCR 8 already present, nothing to do
			return nil
		}
	}

	// 3. Read the 800-luks-header.pcrlock file
	luksLockPath := filepath.Join(PCRLockDir, "800-luks-header.pcrlock")
	luksData, err := os.ReadFile(luksLockPath)
	if err != nil {
		return fmt.Errorf("failed to read luks pcrlock: %w", err)
	}

	var luksLock map[string]interface{}
	if err := json.Unmarshal(luksData, &luksLock); err != nil {
		return fmt.Errorf("failed to parse luks pcrlock: %w", err)
	}

	// 4. Extract hashes
	records, ok := luksLock["records"].([]interface{})
	if !ok || len(records) == 0 {
		return fmt.Errorf("invalid luks pcrlock: no records")
	}

	var pcr8Values []string
	for _, r := range records {
		rec, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if it's PCR 8
		if pcr, ok := rec["pcr"].(float64); !ok || int(pcr) != 8 {
			continue
		}

		digests, ok := rec["digests"].([]interface{})
		if !ok {
			continue
		}

		for _, d := range digests {
			dig, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			if alg, ok := dig["hashAlg"].(string); ok && alg == "sha256" {
				if val, ok := dig["digest"].(string); ok {
					// Compute PCR extension: new_pcr = SHA256(old_pcr || data_hash)
					// PCR 8 starts at all zeros, so we extend from zeros
					extendedVal, err := computePCRExtend(val)
					if err != nil {
						return fmt.Errorf("failed to compute PCR extend: %w", err)
					}
					pcr8Values = append(pcr8Values, extendedVal)
				}
			}
		}
	}

	if len(pcr8Values) == 0 {
		return fmt.Errorf("no sha256 digests found in luks pcrlock")
	}

	if Verbose {
		fmt.Printf("[+] Injecting PCR 8 values from %s: %v\n", luksLockPath, pcr8Values)
	}

	// 5. Add to policy
	newPCR := map[string]interface{}{
		"pcr":    8,
		"values": pcr8Values,
	}
	policy["pcrValues"] = append(pcrValues, newPCR)

	// 6. Write back
	newPolicyData, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal new policy: %w", err)
	}

	// Ensure file ends with newline
	newPolicyData = append(newPolicyData, '\n')

	if err := os.WriteFile(policyPath, newPolicyData, 0644); err != nil {
		return fmt.Errorf("failed to write updated policy: %w", err)
	}

	return nil
}

// computePCRExtend computes PCR extension from a zero-initialized PCR.
// PCR extension formula: new_pcr = SHA256(old_pcr || data_hash)
func computePCRExtend(dataHashHex string) (string, error) {
	dataHash, err := hex.DecodeString(dataHashHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex digest: %w", err)
	}

	// PCR 8 starts at all zeros (32 bytes for SHA256)
	initialPCR := make([]byte, 32)

	// Concatenate old_pcr || data_hash and hash
	h := sha256.New()
	h.Write(initialPCR)
	h.Write(dataHash)
	extended := h.Sum(nil)

	return hex.EncodeToString(extended), nil
}
