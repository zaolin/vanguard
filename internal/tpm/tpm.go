// Package tpm provides TPM 2.0 functionality using native Go.
// This implementation uses google/go-tpm with the tpmdirect API which
// provides native PolicyAuthorizeNV support required for pcrlock tokens.
package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/zaolin/vanguard/init/buildtags"
	"golang.org/x/crypto/pbkdf2"
)

// ErrTPMUnavailable indicates the TPM device is not available.
var ErrTPMUnavailable = errors.New("TPM device not available")

// ErrTPMLockout indicates the TPM is in DA lockout mode.
var ErrTPMLockout = errors.New("TPM is in dictionary attack lockout")

// ErrPCRMismatch indicates PCR policy verification failed.
var ErrPCRMismatch = errors.New("PCR policy mismatch")

// ErrWrongPIN indicates incorrect PIN/password.
var ErrWrongPIN = errors.New("incorrect PIN")

// HashAlgorithm is the TPM hash algorithm type.
type HashAlgorithm = tpm2.TPMAlgID

// Algorithm constants for PCR banks.
const (
	AlgSHA1   = tpm2.TPMAlgSHA1
	AlgSHA256 = tpm2.TPMAlgSHA256
	AlgSHA384 = tpm2.TPMAlgSHA384
	AlgSHA512 = tpm2.TPMAlgSHA512
)

// UnsealOpts contains options for unsealing a TPM-protected secret.
type UnsealOpts struct {
	Public     []byte        // TPM public blob
	Private    []byte        // TPM private blob
	PCRs       []int         // PCR indices (empty for pcrlock)
	Bank       HashAlgorithm // PCR hash algorithm
	PolicyHash []byte        // Expected policy hash
	AuthValue  []byte        // PIN/password (raw)
	Salt       []byte        // Salt for PBKDF2 (systemd uses this)
	PrimaryAlg string        // "ecc" or "rsa"
	UsePCRLock bool          // True for pcrlock-based tokens
	PCRLockNV  uint32        // NV index for pcrlock (0 = default 0x01c20000)
	SRKHandle  uint32        // Persistent SRK handle (0 = create transient)
}

// LockoutStatus contains TPM dictionary attack lockout information.
type LockoutStatus struct {
	InLockout       bool
	LockoutCounter  uint64
	MaxAuthFail     uint64
	LockoutRecovery uint64 // seconds to wait for recovery
}

// Client provides TPM 2.0 operations.
type Client struct {
	device string
}

// DefaultDevice is the default TPM device path.
const DefaultDevice = "/dev/tpmrm0"

// FallbackDevice is used if the resource manager is unavailable.
const FallbackDevice = "/dev/tpm0"

// DefaultPCRLockNV is the default NV index for systemd-pcrlock.
const DefaultPCRLockNV = 0x01c20000

// New creates a new TPM client.
func New() *Client {
	return &Client{device: DefaultDevice}
}

// NewWithDevice creates a new TPM client with a specific device path.
func NewWithDevice(device string) *Client {
	return &Client{device: device}
}

// WaitForDevice waits for the TPM device to become available.
// Returns true if the device is ready, false if timeout.
func (c *Client) WaitForDevice(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	devices := []string{c.device, FallbackDevice}

	for time.Now().Before(deadline) {
		for _, dev := range devices {
			if _, err := os.Stat(dev); err == nil {
				c.device = dev
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// openTPM opens a connection to the TPM device.
func (c *Client) openTPM() (transport.TPMCloser, error) {
	tpm, err := linuxtpm.Open(c.device)
	if err != nil {
		// Try fallback device
		if c.device == DefaultDevice {
			tpm, err = linuxtpm.Open(FallbackDevice)
			if err == nil {
				c.device = FallbackDevice
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTPMUnavailable, err)
	}
	return tpm, nil
}

// GetLockoutStatus reads the TPM lockout status.
func (c *Client) GetLockoutStatus() (*LockoutStatus, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	status := &LockoutStatus{}

	// Read TPM properties for lockout info
	lockoutCounter, err := getTPMProperty(tpm, tpm2.TPMPTLockoutCounter)
	if err == nil {
		status.LockoutCounter = uint64(lockoutCounter)
	}

	maxAuthFail, err := getTPMProperty(tpm, tpm2.TPMPTMaxAuthFail)
	if err == nil {
		status.MaxAuthFail = uint64(maxAuthFail)
	}

	lockoutRecovery, err := getTPMProperty(tpm, tpm2.TPMPTLockoutRecovery)
	if err == nil {
		status.LockoutRecovery = uint64(lockoutRecovery)
	}

	// Check if in lockout
	if status.MaxAuthFail > 0 && status.LockoutCounter >= status.MaxAuthFail {
		status.InLockout = true
	}

	return status, nil
}

// getTPMProperty reads a single TPM property.
func getTPMProperty(tpm transport.TPM, prop tpm2.TPMPT) (uint32, error) {
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(prop),
		PropertyCount: 1,
	}
	rsp, err := getCapCmd.Execute(tpm)
	if err != nil {
		return 0, err
	}

	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	if len(props.TPMProperty) == 0 {
		return 0, errors.New("no property returned")
	}
	return props.TPMProperty[0].Value, nil
}

// ReadPCRs reads the specified PCRs from the TPM.
// Returns a map of PCR index to raw value.
func (c *Client) ReadPCRs(bank HashAlgorithm, pcrs []int) (map[int][]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      bank,
			PCRSelect: pcrsToBitmap(pcrs),
		}},
	}

	pcrReadCmd := tpm2.PCRRead{PCRSelectionIn: pcrSelection}
	rsp, err := pcrReadCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	result := make(map[int][]byte)
	for i, digest := range rsp.PCRValues.Digests {
		if i < len(pcrs) {
			result[pcrs[i]] = digest.Buffer
		}
	}

	return result, nil
}

// pcrsToBitmap converts a list of PCR indices to a PCR select bitmap.
func pcrsToBitmap(pcrs []int) []byte {
	// PCR select is a bitmap, 3 bytes for PCRs 0-23
	bitmap := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr >= 0 && pcr < 24 {
			bitmap[pcr/8] |= 1 << (pcr % 8)
		}
	}
	return bitmap
}

// Unseal unseals data using the TPM with PCR policy.
// Deprecated: Use UnsealWithOpts instead.
func (c *Client) Unseal(public, private []byte, pcrs []int, bank HashAlgorithm, policyHash, authValue []byte, primaryAlg string) ([]byte, error) {
	return c.UnsealWithOpts(UnsealOpts{
		Public:     public,
		Private:    private,
		PCRs:       pcrs,
		Bank:       bank,
		PolicyHash: policyHash,
		AuthValue:  authValue,
		PrimaryAlg: primaryAlg,
	})
}

// UnsealWithOpts unseals data using the TPM with the given options.
// This is the main entry point for unsealing systemd-tpm2 tokens.
func (c *Client) UnsealWithOpts(opts UnsealOpts) ([]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// Create or use SRK
	var srk tpm2.AuthHandle
	var srkCleanup func()

	if opts.SRKHandle != 0 {
		// Use persistent SRK - read its name for AuthHandle
		pubRsp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(opts.SRKHandle)}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to read persistent SRK: %w", err)
		}
		srk = tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(opts.SRKHandle),
			Name:   pubRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		}
		srkCleanup = func() {}
	} else {
		// Create transient SRK matching the algorithm used during enrollment
		srk, srkCleanup, err = c.createSRK(tpm, opts.PrimaryAlg)
		if err != nil {
			return nil, fmt.Errorf("failed to create primary: %w", err)
		}
	}
	defer srkCleanup()

	// Parse the systemd blob format
	pub, priv, err := parseSystemdBlob(opts.Public, opts.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blob: %w", err)
	}

	// Load the sealed object
	loadRsp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    tpm2.TPM2BPrivate{Buffer: priv},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to load object: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpm)

	needsAuth := len(opts.AuthValue) > 0

	// For pcrlock tokens, use PolicyAuthorizeNV
	if opts.UsePCRLock {
		return c.unsealWithPCRLock(tpm, loadRsp, opts, needsAuth)
	}

	// For traditional tokens, use PCR policy
	return c.unsealWithPCRPolicy(tpm, loadRsp, opts, needsAuth)
}

// parseSystemdBlob parses public/private blobs.
// The public blob from systemd is in TPM2B_PUBLIC format.
func parseSystemdBlob(public, private []byte) ([]byte, []byte, error) {
	// Public blob is already in correct format for BytesAs2B
	// Private blob is used directly
	return public, private, nil
}

// unsealWithPCRLock handles pcrlock-based tokens (systemd v255+)
// This uses PolicyAuthorizeNV which is natively supported by google/go-tpm.
func (c *Client) unsealWithPCRLock(tpm transport.TPM, loadRsp *tpm2.LoadResponse, opts UnsealOpts, needsAuth bool) ([]byte, error) {
	nvIndex := opts.PCRLockNV
	if nvIndex == 0 {
		nvIndex = DefaultPCRLockNV
	}

	// Try different auth value formats
	authVariants := []struct {
		value []byte
		name  string
	}{{nil, "none"}}

	if needsAuth && len(opts.AuthValue) > 0 {
		// When salt is available, use PBKDF2-HMAC-SHA256 (systemd's method)
		if len(opts.Salt) > 0 {
			pbkdf2Key := DeriveAuthValue(string(opts.AuthValue), opts.Salt)
			authVariants = []struct {
				value []byte
				name  string
			}{
				{pbkdf2Key, "pbkdf2"},
				{nil, "empty"},
			}
		} else {
			// No salt - try legacy methods
			hashedPIN := HashPIN(string(opts.AuthValue))
			authVariants = []struct {
				value []byte
				name  string
			}{
				{hashedPIN, "sha256-hashed"},
				{opts.AuthValue, "raw"},
			}
		}
	}

	var lastErr error
	for _, auth := range authVariants {
		// Create policy session with auth value BOUND to the loaded object
		// When using PolicyAuthValue, the auth value must be bound to the entity
		var sess tpm2.Session
		var cleanup func() error
		var err error

		if needsAuth && len(auth.value) > 0 {
			// Bound() ties the auth value to the specific object we're unsealing
			sess, cleanup, err = tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16,
				tpm2.Bound(loadRsp.ObjectHandle, loadRsp.Name, auth.value))
		} else {
			sess, cleanup, err = tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create policy session: %w", err)
		}

		// Build policy: PolicyAuthValue (if PIN) -> PolicyAuthorizeNV
		if needsAuth {
			_, err := tpm2.PolicyAuthValue{PolicySession: sess.Handle()}.Execute(tpm)
			if err != nil {
				cleanup()
				lastErr = fmt.Errorf("PolicyAuthValue failed: %w", err)
				continue
			}
		}

		// PolicyAuthorizeNV - the key feature for pcrlock tokens
		// Use owner auth for authorization (empty password)
		_, err = tpm2.PolicyAuthorizeNV{
			AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:       tpm2.TPMHandle(nvIndex),
			PolicySession: sess.Handle(),
		}.Execute(tpm)
		if err != nil {
			cleanup()
			lastErr = fmt.Errorf("PolicyAuthorizeNV failed: %w", err)
			continue
		}

		// Verify policy digest if provided
		if len(opts.PolicyHash) > 0 {
			digestRsp, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("PolicyGetDigest failed: %w", err)
			}
			if !bytes.Equal(digestRsp.PolicyDigest.Buffer, opts.PolicyHash) {
				cleanup()
				lastErr = fmt.Errorf("%w: policy digest mismatch", ErrPCRMismatch)
				continue
			}
		}

		// Create handle with policy session as Auth
		// The session carries the auth value for HMAC computation
		loadedHandle := tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   sess,
		}

		// Unseal - session is passed via AuthHandle.Auth, not to Execute()
		unsealRsp, err := tpm2.Unseal{ItemHandle: loadedHandle}.Execute(tpm)
		cleanup()

		if err == nil {
			return unsealRsp.OutData.Buffer, nil
		}

		lastErr = classifyUnsealError(err)
		if errors.Is(lastErr, ErrTPMLockout) {
			return nil, lastErr
		}

		if !needsAuth {
			break
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrPCRMismatch
}

// unsealWithPCRPolicy handles traditional PCR-bound tokens
func (c *Client) unsealWithPCRPolicy(tpm transport.TPM, loadRsp *tpm2.LoadResponse, opts UnsealOpts, needsAuth bool) ([]byte, error) {
	// Try different auth value formats
	authVariants := []struct {
		value []byte
		name  string
	}{{nil, "none"}}

	if needsAuth && len(opts.AuthValue) > 0 {
		// When salt is available, use PBKDF2-HMAC-SHA256 (systemd's method)
		// Otherwise fall back to plain SHA256 (legacy)
		if len(opts.Salt) > 0 {
			pbkdf2Key := DeriveAuthValue(string(opts.AuthValue), opts.Salt)
			buildtags.Debug("tpm debug: PIN len=%d, salt len=%d, pbkdf2=%x\n", len(opts.AuthValue), len(opts.Salt), pbkdf2Key[:8])
			authVariants = []struct {
				value []byte
				name  string
			}{
				{pbkdf2Key, "pbkdf2"},
				{nil, "empty"}, // Try empty in case PIN wasn't actually enrolled
			}
		} else {
			// No salt - try legacy methods
			hashedPIN := HashPIN(string(opts.AuthValue))
			buildtags.Debug("tpm debug: PIN len=%d, hashed=%x (no salt)\n", len(opts.AuthValue), hashedPIN[:8])
			authVariants = []struct {
				value []byte
				name  string
			}{
				{hashedPIN, "sha256-hashed"},
				{opts.AuthValue, "raw"},
				{nil, "empty"},
			}
		}
	}

	var lastErr error
	for _, auth := range authVariants {
		buildtags.Debug("tpm debug: trying auth variant '%s'\n", auth.name)

		// Create policy session with auth value BOUND to the loaded object
		// When using PolicyAuthValue, the auth value must be bound to the entity
		// that we're authorizing - this provides the auth value for HMAC calculation
		var sess tpm2.Session
		var cleanup func() error
		var err error

		if needsAuth && len(auth.value) > 0 {
			// Bound() ties the auth value to the specific object we're unsealing
			sess, cleanup, err = tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16,
				tpm2.Bound(loadRsp.ObjectHandle, loadRsp.Name, auth.value))
		} else {
			sess, cleanup, err = tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to start policy session: %w", err)
		}

		// Build policy in correct order: PolicyAuthValue (if PIN) -> PolicyPCR
		// This order matches systemd-tpm2's policy construction
		if needsAuth {
			_, err := tpm2.PolicyAuthValue{PolicySession: sess.Handle()}.Execute(tpm)
			if err != nil {
				cleanup()
				lastErr = fmt.Errorf("PolicyAuthValue failed: %w", err)
				buildtags.Debug("tpm debug: PolicyAuthValue failed: %v\n", err)
				continue
			}
		}

		// Apply PCR policy only if PCRs are specified
		if len(opts.PCRs) > 0 {
			pcrSelection := tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      opts.Bank,
					PCRSelect: pcrsToBitmap(opts.PCRs),
				}},
			}
			_, err := tpm2.PolicyPCR{
				PolicySession: sess.Handle(),
				Pcrs:          pcrSelection,
			}.Execute(tpm)
			if err != nil {
				cleanup()
				lastErr = fmt.Errorf("PolicyPCR failed: %w", err)
				continue
			}
		}

		// Verify policy digest
		if len(opts.PolicyHash) > 0 {
			digestRsp, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("PolicyGetDigest failed: %w", err)
			}
			if !bytes.Equal(digestRsp.PolicyDigest.Buffer, opts.PolicyHash) {
				cleanup()
				lastErr = fmt.Errorf("%w: policy digest mismatch", ErrPCRMismatch)
				continue
			}
		}

		// Create handle with policy session as Auth
		// The session carries the auth value for HMAC computation
		loadedHandle := tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   sess,
		}

		// Unseal - session is passed via AuthHandle.Auth, not to Execute()
		unsealRsp, err := tpm2.Unseal{ItemHandle: loadedHandle}.Execute(tpm)
		cleanup()

		if err == nil {
			buildtags.Debug("tpm debug: unseal succeeded with '%s'\n", auth.name)
			return unsealRsp.OutData.Buffer, nil
		}

		buildtags.Debug("tpm debug: unseal failed with '%s': %v\n", auth.name, err)
		lastErr = classifyUnsealError(err)
		if errors.Is(lastErr, ErrTPMLockout) {
			return nil, lastErr
		}

		if !needsAuth {
			break
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrPCRMismatch
}

// createSRK creates the Storage Root Key for unsealing.
// primaryAlg should be "ecc" or "rsa" to match what was used during enrollment.
func (c *Client) createSRK(tpm transport.TPM, primaryAlg string) (tpm2.AuthHandle, func(), error) {
	var template tpm2.TPMTPublic

	if primaryAlg == "rsa" {
		// RSA SRK template matching systemd-tpm2
		template = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:             true,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				NoDA:                 true,
				Restricted:           true,
				Decrypt:              true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					},
					Scheme:   tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{}),
		}
	} else {
		// ECC SRK template matching systemd-tpm2 (default)
		template = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:             true,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				NoDA:                 true,
				Restricted:           true,
				Decrypt:              true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					},
					Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
					CurveID: tpm2.TPMECCNistP256,
					KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
				},
			),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
		}
	}

	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(template),
	}

	rsp, err := createPrimaryCmd.Execute(tpm)
	if err != nil {
		return tpm2.AuthHandle{}, nil, err
	}

	srk := tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}

	cleanup := func() {
		tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm)
	}

	return srk, cleanup, nil
}

// NVReadPublic reads the public area of an NV index.
func (c *Client) NVReadPublic(index uint32) ([]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	nvReadPubCmd := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}
	rsp, err := nvReadPubCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("NVReadPublic failed: %w", err)
	}

	// Marshal the NV public data to bytes
	return rsp.NVPublic.Bytes(), nil
}

// ParsePCRBank converts a bank name string to TPM algorithm.
func ParsePCRBank(bank string) HashAlgorithm {
	switch bank {
	case "sha1":
		return AlgSHA1
	case "sha256", "":
		return AlgSHA256
	case "sha384":
		return AlgSHA384
	case "sha512":
		return AlgSHA512
	default:
		return AlgSHA256
	}
}

// HashPIN hashes a PIN using SHA-256 for TPM2 auth value (legacy).
// Use DeriveAuthValue when salt is available.
func HashPIN(pin string) []byte {
	hash := sha256.Sum256([]byte(pin))
	return hash[:]
}

// DeriveAuthValue derives the TPM auth value from a PIN using PBKDF2-HMAC-SHA256.
// This matches systemd's tpm2_util_pbkdf2_hmac_sha256 function.
// The salt is provided in the token JSON as "tpm2-salt".
func DeriveAuthValue(pin string, salt []byte) []byte {
	// systemd uses PBKDF2 with 1 iteration (single key derivation, not stretching)
	// The output length matches SHA256 (32 bytes)
	return pbkdf2.Key([]byte(pin), salt, 1, sha256.Size, sha256.New)
}

// ParseBlob parses a systemd-tpm2 blob into private and public components.
// The blob format is: <2-byte private size><private data><2-byte public size><public data>
func ParseBlob(blob []byte) (private, public []byte, err error) {
	if len(blob) < 4 {
		return nil, nil, errors.New("blob too short")
	}

	privateSize := int(binary.BigEndian.Uint16(blob[:2]))
	blob = blob[2:]

	if len(blob) < privateSize+2 {
		return nil, nil, errors.New("blob truncated at private data")
	}

	private = blob[:privateSize]
	blob = blob[privateSize:]

	publicSize := int(binary.BigEndian.Uint16(blob[:2]))
	blob = blob[2:]

	if len(blob) < publicSize {
		return nil, nil, errors.New("blob truncated at public data")
	}

	public = blob[:publicSize]

	return private, public, nil
}

// classifyUnsealError converts TPM errors to semantic errors.
func classifyUnsealError(err error) error {
	// Check for TPM response codes from google/go-tpm
	// TPMRC implements the error interface
	var tpmRC tpm2.TPMRC
	if errors.As(err, &tpmRC) {
		// Check for warnings (like lockout)
		if tpmRC.IsWarning() {
			if errors.Is(tpmRC, tpm2.TPMRCLockout) {
				return fmt.Errorf("%w: %v", ErrTPMLockout, err)
			}
		}
		// Check for specific error codes using Is() which handles FMT1 errors
		if errors.Is(tpmRC, tpm2.TPMRCAuthFail) {
			return fmt.Errorf("%w: %v", ErrWrongPIN, err)
		}
		if errors.Is(tpmRC, tpm2.TPMRCPolicyFail) {
			return fmt.Errorf("%w: %v", ErrPCRMismatch, err)
		}
		if errors.Is(tpmRC, tpm2.TPMRCBadAuth) {
			return fmt.Errorf("%w: %v", ErrWrongPIN, err)
		}
	}

	// Check for format-1 errors with additional context
	var fmt1Err tpm2.TPMFmt1Error
	if errors.As(err, &fmt1Err) {
		errStr := fmt1Err.Error()
		if containsAny(errStr, "AUTH_FAIL", "BAD_AUTH") {
			return fmt.Errorf("%w: %v", ErrWrongPIN, err)
		}
		if containsAny(errStr, "POLICY_FAIL") {
			return fmt.Errorf("%w: %v", ErrPCRMismatch, err)
		}
	}

	// Fallback to string matching for any other errors
	errStr := err.Error()
	if containsAny(errStr, "authorization", "auth fail", "HMAC check failed", "AUTH_FAIL", "BAD_AUTH") {
		return fmt.Errorf("%w: %v", ErrWrongPIN, err)
	}
	if containsAny(errStr, "policy", "POLICY_FAIL") {
		return fmt.Errorf("%w: %v", ErrPCRMismatch, err)
	}
	if containsAny(errStr, "lockout", "LOCKOUT") {
		return fmt.Errorf("%w: %v", ErrTPMLockout, err)
	}

	return err
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
