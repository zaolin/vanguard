package luks

import (
	"encoding/base64"
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
type systemdTPM2TokenPayload struct {
	Blob         string `json:"tpm2-blob"`          // base64 encoded
	PCRs         []int  `json:"tpm2-pcrs"`          // e.g., [7, 11, 14] (legacy)
	PCRBank      string `json:"tpm2-pcr-bank"`      // sha1 or sha256
	PolicyHash   string `json:"tpm2-policy-hash"`   // hex encoded
	PIN          bool   `json:"tpm2-pin"`
	Salt         string `json:"tpm2-salt"`          // base64 encoded salt for PBKDF2
	PrimaryAlg   string `json:"tpm2-primary-alg"`   // "ecc" or "rsa"
	PCRLock      bool   `json:"tpm2-pcrlock"`       // true if pcrlock is used (v255+)
	PCRLockNV    uint32 `json:"tpm2-pcrlock-nv"`    // NV index for pcrlock policy
	SRKHandle    uint32 `json:"tpm2-srk"`           // persistent SRK handle (optional)
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
	buildtags.Debug("  salt-len: %d\n", len(payload.Salt))
	buildtags.Debug("  primary-alg: %s\n", payload.PrimaryAlg)
	buildtags.Debug("  pcrlock: %v\n", payload.PCRLock)
	buildtags.Debug("  pcrlock-nv: 0x%x\n", payload.PCRLockNV)
	buildtags.Debug("  policy-hash: %s\n", payload.PolicyHash)
	buildtags.Debug("  blob-len: %d\n", len(payload.Blob))

	// Decode base64 blob
	blob, err := base64.StdEncoding.DecodeString(payload.Blob)
	if err != nil {
		return nil, err
	}

	// Decode base64 salt (for PBKDF2 PIN derivation)
	var salt []byte
	if payload.Salt != "" {
		salt, err = base64.StdEncoding.DecodeString(payload.Salt)
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

	// Detect pcrlock usage: only if explicit flag or NV index is set
	// Empty PCRs with policy hash could just be a PIN-only token (no PCR binding)
	usePCRLock := payload.PCRLock || payload.PCRLockNV != 0
	if usePCRLock {
		buildtags.Debug("tpm2 token: pcrlock mode (nv=0x%x)\n", payload.PCRLockNV)
	} else if len(payload.PCRs) == 0 && payload.PIN {
		buildtags.Debug("tpm2 token: PIN-only mode (no PCRs)\n")
	}

	return &TPM2Token{
		Blob:       blob,
		PCRs:       payload.PCRs,
		PCRBank:    pcrBank,
		PolicyHash: policyHash,
		NeedsPIN:   payload.PIN,
		Salt:       salt,
		PrimaryAlg: primaryAlg,
		UsePCRLock: usePCRLock,
		PCRLockNV:  payload.PCRLockNV,
		SRKHandle:  payload.SRKHandle,
		Keyslots:   token.Slots,
	}, nil
}

// Unseal uses the TPM to unseal the LUKS password.
// If PIN is required, it should be provided as a hashed value.
func (t *TPM2Token) Unseal(tpmClient *intpm.Client, pin []byte) ([]byte, error) {
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

	// Build unseal options
	opts := intpm.UnsealOpts{
		Public:     public,
		Private:    private,
		PCRs:       t.PCRs,
		Bank:       bank,
		PolicyHash: t.PolicyHash,
		AuthValue:  authValue,
		Salt:       t.Salt, // For PBKDF2 PIN derivation
		PrimaryAlg: t.PrimaryAlg,
		UsePCRLock: t.UsePCRLock,
		PCRLockNV:  t.PCRLockNV,
		SRKHandle:  t.SRKHandle,
	}

	// Call TPM unseal - returns the raw password bytes
	return tpmClient.UnsealWithOpts(opts)
}
