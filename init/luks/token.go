package luks

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/anatol/luks.go"
	"github.com/zaolin/vanguard/init/buildtags"
	intpm "github.com/zaolin/vanguard/internal/tpm"
)

// TPM2Token represents a parsed systemd-tpm2 token.
type TPM2Token struct {
	// Blob is the TPM2 sealed blob containing private and public key material.
	Blob []byte
	// PCRs are the PCR indices bound to this token (legacy, empty for pcrlock).
	PCRs []int
	// PCRBank is the hash algorithm for PCR values (sha1, sha256, etc.).
	PCRBank string
	// PolicyHash is the expected TPM policy hash.
	PolicyHash []byte
	// NeedsPIN indicates whether a PIN is required for unsealing.
	NeedsPIN bool
	// Salt is the salt used for PBKDF2 PIN derivation (systemd uses this).
	Salt []byte
	// PrimaryAlg is the algorithm for the primary key ("ecc" or "rsa").
	PrimaryAlg string
	// UsePCRLock indicates pcrlock is used instead of direct PCR binding (v255+).
	UsePCRLock bool
	// PCRLockNV is the NV index containing the pcrlock policy.
	PCRLockNV uint32
	// SRKHandle is a persistent SRK handle (0 = create transient SRK).
	SRKHandle uint32
	// Keyslots are the LUKS keyslots this token unlocks.
	Keyslots []int
}

// systemdTPM2TokenPayload is the JSON structure of a systemd-tpm2 token.
// Note: systemd uses both hyphen and underscore variants in different versions.
type systemdTPM2TokenPayload struct {
	Blob             string `json:"tpm2-blob"`        // base64 encoded
	PCRs             []int  `json:"tpm2-pcrs"`        // e.g., [7, 11, 14] (legacy)
	PCRBank          string `json:"tpm2-pcr-bank"`    // sha1 or sha256
	PolicyHash       string `json:"tpm2-policy-hash"` // hex encoded
	PIN              bool   `json:"tpm2-pin"`
	Salt             string `json:"tpm2-salt"`        // base64 encoded salt for PBKDF2
	SaltAlt          string `json:"tpm2_salt"`        // underscore variant (systemd v255+)
	PrimaryAlg       string `json:"tpm2-primary-alg"` // "ecc" or "rsa"
	PCRLock          bool   `json:"tpm2-pcrlock"`     // true if pcrlock is used (v255+)
	PCRLockAlt       bool   `json:"tpm2_pcrlock"`     // underscore variant (systemd v255+)
	PCRLockNV        uint32 `json:"tpm2-pcrlock-nv"`  // NV index for pcrlock policy
	PCRLockNVDataAlt string `json:"tpm2_pcrlock_nv"`  // underscore variant - base64 NV policy data (systemd v255+)
	SRKHandle        uint32 `json:"tpm2-srk"`         // persistent SRK handle (optional)
	SRKDataAlt       string `json:"tpm2_srk"`         // underscore variant - base64 SRK public data (systemd v255+)
}

// ParseTPM2Token parses a luks.Token into a TPM2Token.
func ParseTPM2Token(token luks.Token) (*TPM2Token, error) {
	if token.Type != "systemd-tpm2" {
		return nil, errors.New("not a systemd-tpm2 token")
	}

	var payload systemdTPM2TokenPayload
	if err := json.Unmarshal(token.Payload, &payload); err != nil {
		return nil, err
	}

	// Debug: print all parsed fields (only in debug builds)
	buildtags.Debug("tpm2 token debug:\n")
	buildtags.Debug("  pcrs: %v\n", payload.PCRs)
	buildtags.Debug("  pcr-bank: %s\n", payload.PCRBank)
	buildtags.Debug("  pin: %v\n", payload.PIN)
	buildtags.Debug("  salt-len: %d (alt: %d)\n", len(payload.Salt), len(payload.SaltAlt))
	buildtags.Debug("  primary-alg: %s\n", payload.PrimaryAlg)
	buildtags.Debug("  pcrlock: %v (alt: %v)\n", payload.PCRLock, payload.PCRLockAlt)
	buildtags.Debug("  pcrlock-nv: 0x%x (alt present: %v)\n", payload.PCRLockNV, payload.PCRLockNVDataAlt != "")
	buildtags.Debug("  pcrlock-nv-data-alt: %q\n", payload.PCRLockNVDataAlt)
	buildtags.Debug("  srk: 0x%x (alt present: %v)\n", payload.SRKHandle, payload.SRKDataAlt != "")
	buildtags.Debug("  policy-hash: %s\n", payload.PolicyHash)
	buildtags.Debug("  blob-len: %d\n", len(payload.Blob))

	// Decode base64 blob
	blob, err := base64.StdEncoding.DecodeString(payload.Blob)
	if err != nil {
		return nil, err
	}

	// Decode base64 salt (for PBKDF2 PIN derivation)
	// Use underscore variant as fallback (systemd v255+ uses underscores)
	saltStr := payload.Salt
	if saltStr == "" {
		saltStr = payload.SaltAlt
	}
	var salt []byte
	if saltStr != "" {
		salt, err = base64.StdEncoding.DecodeString(saltStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode salt: %w", err)
		}
		buildtags.Debug("  salt decoded: %d bytes\n", len(salt))
	}

	// Decode hex policy hash
	var policyHash []byte
	if payload.PolicyHash != "" {
		policyHash, err = hex.DecodeString(payload.PolicyHash)
		if err != nil {
			return nil, err
		}
	}

	// Default PCR bank
	pcrBank := payload.PCRBank
	if pcrBank == "" {
		pcrBank = "sha256"
	}

	// Default primary algorithm (systemd defaults to ECC)
	primaryAlg := payload.PrimaryAlg
	if primaryAlg == "" {
		primaryAlg = "ecc"
	}

	// Detect pcrlock usage: check both hyphen and underscore variants
	// systemd v255+ uses underscore variants (tpm2_pcrlock, tpm2_pcrlock_nv)
	// Note: tpm2_pcrlock_nv in v255+ is base64-encoded NV index data, not a uint32
	buildtags.Debug("tpm2 token: pcrlock detection - PCRLock=%v, PCRLockAlt=%v, PCRLockNV=0x%x, PCRLockNVDataAlt=%v\n",
		payload.PCRLock, payload.PCRLockAlt, payload.PCRLockNV, payload.PCRLockNVDataAlt != "")
	usePCRLock := payload.PCRLock || payload.PCRLockAlt || payload.PCRLockNV != 0 || payload.PCRLockNVDataAlt != ""
	pcrlockNV := payload.PCRLockNV
	if pcrlockNV == 0 && payload.PCRLockNVDataAlt != "" {
		// Decode base64 NV index data for v255+ format
		// The NV index is typically the first 4 bytes in big-endian
		nvData, err := base64.StdEncoding.DecodeString(payload.PCRLockNVDataAlt)
		if err == nil && len(nvData) >= 4 {
			pcrlockNV = binary.BigEndian.Uint32(nvData[:4])
		}
	}
	if usePCRLock {
		buildtags.Debug("tpm2 token: pcrlock mode (nv=0x%x)\n", pcrlockNV)
	} else if len(payload.PCRs) == 0 && payload.PIN {
		buildtags.Debug("tpm2 token: PIN-only mode (no PCRs)\n")
	}

	// Note: tpm2_srk in systemd v255+ is not a handle but SRK public data
	// For now, we only support the tpm2-srk handle variant (hyphen format)
	srkHandle := payload.SRKHandle

	return &TPM2Token{
		Blob:       blob,
		PCRs:       payload.PCRs,
		PCRBank:    pcrBank,
		PolicyHash: policyHash,
		NeedsPIN:   payload.PIN,
		Salt:       salt,
		PrimaryAlg: primaryAlg,
		UsePCRLock: usePCRLock,
		PCRLockNV:  pcrlockNV,
		SRKHandle:  srkHandle,
		Keyslots:   token.Slots,
	}, nil
}

// Unseal uses the TPM to unseal the LUKS password.
// If PIN is required, it should be provided as a hashed value.
// skipPolicyHashVerify should be true for PIN-only tokens (no PCRs).
func (t *TPM2Token) Unseal(tpmClient *intpm.Client, pin []byte, skipPolicyHashVerify bool) ([]byte, error) {
	// Parse the blob to extract private and public key material
	private, public, err := intpm.ParseBlob(t.Blob)
	if err != nil {
		return nil, err
	}

	// Convert PCR bank string to TPM algorithm
	bank := intpm.ParsePCRBank(t.PCRBank)

	// For TPM authorization, we need to try both:
	// 1. Raw PIN (some configurations)
	// 2. SHA256-hashed PIN (systemd default)
	// The authValue will be tried both ways by the TPM client
	var authValue []byte
	if len(pin) > 0 {
		authValue = pin // Pass raw PIN, TPM client will try both raw and hashed
	}

	buildtags.Debug("tpm token debug: PIN received (len=%d), Salt (len=%d)\n", len(pin), len(t.Salt))
	if len(pin) > 0 {
		buildtags.Debug("tpm token debug: PIN value (hex): %x\n", pin)
	}
	if len(t.Salt) > 0 {
		buildtags.Debug("tpm token debug: Salt value (hex): %x\n", t.Salt)
	}

	// Build unseal options
	opts := intpm.UnsealOpts{
		Public:               public,
		Private:              private,
		PCRs:                 t.PCRs,
		Bank:                 bank,
		PolicyHash:           t.PolicyHash,
		AuthValue:            authValue,
		Salt:                 t.Salt, // For PBKDF2 PIN derivation
		PrimaryAlg:           t.PrimaryAlg,
		UsePCRLock:           t.UsePCRLock,
		PCRLockNV:            t.PCRLockNV,
		SRKHandle:            t.SRKHandle,
		SkipPolicyHashVerify: skipPolicyHashVerify,
	}

	// Call TPM unseal - returns the raw password bytes
	return tpmClient.UnsealWithOpts(opts)
}
