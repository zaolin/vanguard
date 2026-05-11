// Package tpm provides TPM 2.0 functionality using native Go.
// This implementation uses google/go-tpm with the tpmdirect API which
// provides native PolicyAuthorizeNV support required for pcrlock tokens.
package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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

// PCRPrediction represents a predicted PCR value with one or more variants.
type PCRPrediction struct {
	PCR    int      // PCR index (0-23)
	Values [][]byte // Predicted PCR digest values (hex-decoded)
}

// UnsealOpts contains options for unsealing a TPM-protected secret.
type UnsealOpts struct {
	Public               []byte          // TPM public blob
	Private              []byte          // TPM private blob
	PCRs                 []int           // PCR indices (empty for pcrlock)
	Bank                 HashAlgorithm   // PCR hash algorithm
	PolicyHash           []byte          // Expected policy hash
	AuthValue            []byte          // PIN/password (raw)
	Salt                 []byte          // Salt for PBKDF2 (systemd uses this) - ONLY for enrollment
	PrimaryAlg           string          // "ecc" or "rsa"
	UsePCRLock           bool            // True for pcrlock-based tokens
	PCRLockNV            uint32          // NV index for pcrlock (0 = default 0x01c20000)
	SRKHandle            uint32          // Persistent SRK handle (0 = create transient)
	SRKData              []byte          // Serialized SRK public data (tpm2_srk from systemd v255+)
	SkipPolicyHashVerify bool            // Skip policy hash verification (for PIN-only tokens)
	PCRPredictions       []PCRPrediction // Predicted PCR values for pcrlock super-PCR policy
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
	buildtags.Debug("tpm: === UnsealWithOpts starting ===\n")
	buildtags.Debug("tpm: UsePCRLock: %v\n", opts.UsePCRLock)
	buildtags.Debug("tpm: Needs auth: %v\n", len(opts.AuthValue) > 0)
	buildtags.Debug("tpm: PCRLockNV: 0x%x\n", opts.PCRLockNV)
	buildtags.Debug("tpm: PolicyHash: %x\n", opts.PolicyHash)
	buildtags.Debug("tpm: SRKData length: %d\n", len(opts.SRKData))
	buildtags.Debug("tpm: SRKHandle: 0x%x\n", opts.SRKHandle)

	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// Create or use SRK
	var srk tpm2.AuthHandle
	var srkCleanup func()

	// Priority: SRKData (tpm2_srk) > SRKHandle > create transient
	if len(opts.SRKData) > 0 {
		// Load SRK from public data (systemd v255+ format)
		buildtags.Debug("tpm: SRK source: tpm2_srk data (%d bytes)\n", len(opts.SRKData))
		srk, srkCleanup, err = c.loadExternalSRK(tpm, opts.SRKData)
		if err != nil {
			return nil, fmt.Errorf("failed to load SRK from data: %w", err)
		}
	} else if opts.SRKHandle != 0 {
		// Use persistent SRK - read its name for AuthHandle
		buildtags.Debug("tpm: SRK source: persistent handle 0x%x\n", opts.SRKHandle)
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
		buildtags.Debug("tpm: SRK source: transient (PrimaryAlg=%s)\n", opts.PrimaryAlg)
		srk, srkCleanup, err = c.createSRK(tpm, opts.PrimaryAlg)
		if err != nil {
			return nil, fmt.Errorf("failed to create primary: %w", err)
		}
	}
	defer srkCleanup()
	buildtags.Debug("tpm: SRK handle: 0x%x, name: %x\n", srk.Handle, srk.Name)

	// Parse the systemd blob format
	pub, priv, err := parseSystemdBlob(opts.Public, opts.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blob: %w", err)
	}
	buildtags.Debug("tpm: Blob parsed - public: %d bytes, private: %d bytes\n", len(pub), len(priv))

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
	buildtags.Debug("tpm: Sealed object loaded - handle: 0x%x, name: %x\n", loadRsp.ObjectHandle, loadRsp.Name)

	needsAuth := len(opts.AuthValue) > 0
	buildtags.Debug("tpm: Calling unseal function - UsePCRLock=%v, needsAuth=%v\n", opts.UsePCRLock, needsAuth)

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

// isValidNVIndex checks if an NV index is in a valid range for owner or platform hierarchy.
// NV index ranges:
//   - Owner hierarchy: 0x01800000 - 0x01FFFFFF
//   - Platform hierarchy: 0x02000000 - 0x02FFFFFF
//   - 0x18188a3 is an invalid NV index (falls outside valid ranges)
func isValidNVIndex(index uint32) bool {
	if index == 0 {
		return false
	}
	// Check owner hierarchy range (0x01800000 - 0x01FFFFFF)
	if index >= 0x01800000 && index <= 0x01FFFFFF {
		return true
	}
	// Check platform hierarchy range (0x02000000 - 0x02FFFFFF)
	if index >= 0x02000000 && index <= 0x02FFFFFF {
		return true
	}
	return false
}

// unsealWithPCRLock handles pcrlock-based tokens (systemd v255+)
// The correct sequence is:
//  1. Build super-PCR policy on the session (PolicyPCR + PolicyOR for multi-value PCRs)
//  2. Call PolicyAuthorizeNV (which checks session digest matches NV index contents)
//  3. Call PolicyAuthValue if PIN is needed
//  4. Unseal
func (c *Client) unsealWithPCRLock(tpm transport.TPM, loadRsp *tpm2.LoadResponse, opts UnsealOpts, needsAuth bool) ([]byte, error) {
	nvIndex := opts.PCRLockNV

	if !isValidNVIndex(nvIndex) {
		buildtags.Debug("tpm: NV index from token (0x%x) looks invalid, searching TPM...\n", nvIndex)
		foundIndex, err := c.FindPCRLockNVIndex()
		if err != nil {
			buildtags.Debug("tpm: failed to find PCRLock NV index: %v\n", err)
		} else if foundIndex != 0 {
			nvIndex = foundIndex
		} else {
			nvIndex = DefaultPCRLockNV
		}
		buildtags.Debug("tpm: using NV index: 0x%x\n", nvIndex)
	}

	buildtags.Debug("tpm: Reading NV public for index 0x%x...\n", nvIndex)
	nvReadPublicRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(nvIndex),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("NVReadPublic failed for 0x%x: %w", nvIndex, err)
	}
	buildtags.Debug("tpm: NV index 0x%x, NV Name (%d bytes): %x\n", nvIndex, len(nvReadPublicRsp.NVName.Buffer), nvReadPublicRsp.NVName.Buffer)

	hasPredictions := len(opts.PCRPredictions) > 0
	if hasPredictions {
		buildtags.Debug("tpm: have %d PCR predictions from pcrlock.json\n", len(opts.PCRPredictions))
		for _, pred := range opts.PCRPredictions {
			buildtags.Debug("tpm:   PCR %d: %d variant(s)\n", pred.PCR, len(pred.Values))
		}
	} else {
		buildtags.Debug("tpm: WARNING: no PCR predictions provided, PolicyAuthorizeNV will likely fail\n")
	}

	authVariants := []struct {
		value []byte
		name  string
	}{{nil, "none"}}

	if needsAuth && len(opts.AuthValue) > 0 {
		var authValue []byte
		var authName string
		if len(opts.Salt) > 0 {
			authValue = DerivePinAuthSalted(string(opts.AuthValue), opts.Salt)
			authName = "pbkdf2+b64+sha256+trim"
			buildtags.Debug("tpm: PIN auth value length=%d (%s, salt=%d bytes)\n", len(authValue), authName, len(opts.Salt))
		} else {
			authValue = DerivePinAuthUnseal(string(opts.AuthValue))
			authName = "sha256+trim"
			buildtags.Debug("tpm: PIN auth value length=%d (%s, no salt)\n", len(authValue), authName)
		}

		authVariants = []struct {
			value []byte
			name  string
		}{
			{authValue, authName},
			{nil, "empty"},
		}
	}

	var lastErr error
	for _, auth := range authVariants {
		var sess tpm2.Session
		var cleanup func() error
		var err error

		if needsAuth && len(auth.value) > 0 {
			sess, cleanup, err = newFixedAuthPolicySession(tpm, auth.value)
		} else {
			sess, cleanup, err = tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create policy session: %w", err)
		}

		buildtags.Debug("tpm: policy session 0x%x created (auth=%s)\n", sess.Handle(), auth.name)

		// Step 1: Build super-PCR policy on the session
		// This makes the session digest match what's stored in the NV index
		if hasPredictions {
			buildtags.Debug("tpm: building super-PCR policy on session...\n")
			if err := buildSuperPCRPolicySession(tpm, opts.Bank, opts.PCRPredictions, sess); err != nil {
				cleanup()
				lastErr = fmt.Errorf("build super-PCR policy: %w", err)
				continue
			}

			digestRsp, debugErr := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
			if debugErr == nil {
				buildtags.Debug("tpm: session digest after super-PCR policy: %x\n", digestRsp.PolicyDigest.Buffer)
			}
		}

		// Step 2: PolicyAuthorizeNV
		// The TPM reads the NV index contents and compares with the current session digest.
		// If they match, the session digest is replaced with Hash(0 || CC_PolicyAuthorizeNV || NV_Name)
		buildtags.Debug("tpm: calling PolicyAuthorizeNV with NV index 0x%x...\n", nvIndex)
		_, err = tpm2.PolicyAuthorizeNV{
			AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:       tpm2.NamedHandle{Handle: tpm2.TPMHandle(nvIndex), Name: nvReadPublicRsp.NVName},
			PolicySession: sess.Handle(),
		}.Execute(tpm)
		if err != nil {
			cleanup()
			lastErr = fmt.Errorf("PolicyAuthorizeNV failed: %w", err)
			continue
		}

		buildtags.Debug("tpm: PolicyAuthorizeNV succeeded\n")

		digestAfterAuthNV, debugErr := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
		if debugErr == nil {
			buildtags.Debug("tpm: session digest after PolicyAuthorizeNV: %x\n", digestAfterAuthNV.PolicyDigest.Buffer)
		} else {
			buildtags.Debug("tpm: PolicyGetDigest after PolicyAuthorizeNV failed: %v\n", debugErr)
		}

		// Step 3: PolicyAuthValue if PIN is needed
		if needsAuth && len(auth.value) > 0 {
			_, err := tpm2.PolicyAuthValue{PolicySession: sess.Handle()}.Execute(tpm)
			if err != nil {
				cleanup()
				lastErr = fmt.Errorf("PolicyAuthValue failed: %w", err)
				continue
			}
			buildtags.Debug("tpm: PolicyAuthValue succeeded\n")

			digestAfterAuthVal, debugErr2 := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
			if debugErr2 == nil {
				buildtags.Debug("tpm: session digest after PolicyAuthValue: %x\n", digestAfterAuthVal.PolicyDigest.Buffer)
				buildtags.Debug("tpm: expected authPolicy: %x\n", opts.PolicyHash)
			} else {
				buildtags.Debug("tpm: PolicyGetDigest after PolicyAuthValue failed: %v\n", debugErr2)
			}
		}

		// Step 4: Unseal
		// Note: We do NOT pass an extra HMAC session for encryption.
		// Unseal has no command parameters that require decryption, and
		// an extra session with Encrypt attribute causes TPM_RC_ATTRIBUTES.
		// The policy session handles authorization; the TPM returns OutData directly.
		loadedHandle := tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   sess,
		}

		buildtags.Debug("tpm: calling Unseal...\n")
		unsealRsp, err := tpm2.Unseal{ItemHandle: loadedHandle}.Execute(tpm)
		cleanup()

		if err == nil {
			data := unsealRsp.OutData.Buffer
			if len(data) > 0 {
				buildtags.Debug("tpm: Unseal returned %d bytes (first: 0x%02x, last: 0x%02x)\n", len(data), data[0], data[len(data)-1])
			} else {
				buildtags.Debug("tpm: Unseal returned 0 bytes (empty)\n")
			}
			return data, nil
		}

		buildtags.Debug("tpm: Unseal failed (auth=%s): %v\n", auth.name, err)
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
// unsealWithPCRPolicy handles traditional PCR-bound tokens.
// Uses a policy session for authorization. No extra HMAC session is needed
// for Unseal (the TPM returns OutData directly; an extra HMAC session with
// Encrypt attribute causes TPM_RC_ATTRIBUTES).
func (c *Client) unsealWithPCRPolicy(tpm transport.TPM, loadRsp *tpm2.LoadResponse, opts UnsealOpts, needsAuth bool) ([]byte, error) {
	var authValue []byte
	var authName string

	if needsAuth && len(opts.AuthValue) > 0 {
		if len(opts.Salt) > 0 {
			authValue = DerivePinAuthSalted(string(opts.AuthValue), opts.Salt)
			authName = "pbkdf2+b64+sha256+trim"
			buildtags.Debug("tpm debug: PIN len=%d, using %s (salt=%d bytes)\n", len(opts.AuthValue), authName, len(opts.Salt))
		} else {
			authValue = DerivePinAuthUnseal(string(opts.AuthValue))
			authName = "sha256+trim"
			buildtags.Debug("tpm debug: PIN len=%d, using %s (no salt)\n", len(opts.AuthValue), authName)
		}
		buildtags.Debug("tpm debug: auth value length=%d\n", len(authValue))
	}

	buildtags.Debug("tpm debug: trying auth '%s'\n", authName)

	// Policy session with PolicyAuthValue - matches systemd's approach exactly
	// This tells the TPM what the auth value is for the sealed object
	var policySess tpm2.Session
	var policyCleanup func() error
	var err error

	if needsAuth && len(authValue) > 0 {
		policySess, policyCleanup, err = newFixedAuthPolicySession(tpm, authValue)
		if err != nil {
			return nil, fmt.Errorf("failed to create policy session: %w", err)
		}

		// Call PolicyAuthValue to tell the TPM what the auth value is
		// This is the key step - without it, TPM returns AUTH_UNAVAILABLE
		_, err = tpm2.PolicyAuthValue{PolicySession: policySess.Handle()}.Execute(tpm)
		if err != nil {
			policyCleanup()
			return nil, fmt.Errorf("PolicyAuthValue failed: %w", err)
		}

		buildtags.Debug("tpm debug: Policy session with PolicyAuthValue\n")

		digestRsp, debugErr := tpm2.PolicyGetDigest{PolicySession: policySess.Handle()}.Execute(tpm)
		if debugErr == nil {
			buildtags.Debug("tpm debug: session digest after PolicyAuthValue: %x\n", digestRsp.PolicyDigest.Buffer)
			buildtags.Debug("tpm debug: expected authPolicy: %x\n", opts.PolicyHash)
		}
	}

	// Create handle with Policy session for authorization
	auth := policySess
	if auth == nil {
		auth = tpm2.PasswordAuth(nil)
	}
	loadedHandle := tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   auth,
	}

	// Unseal with policy session only (no extra HMAC session).
	// Unseal has no command parameters that require decryption, and
	// an extra session with Encrypt attribute causes TPM_RC_ATTRIBUTES.
	buildtags.Debug("tpm debug: Calling Unseal with policy session (auth, no extra session)\n")
	var unsealRsp *tpm2.UnsealResponse
	unsealRsp, err = tpm2.Unseal{ItemHandle: loadedHandle}.Execute(tpm)

	// Cleanup sessions
	if policyCleanup != nil {
		policyCleanup()
	}

	if err == nil {
		data := unsealRsp.OutData.Buffer
		if len(data) > 0 {
			buildtags.Debug("tpm debug: Unseal returned %d bytes (first: 0x%02x, last: 0x%02x)\n", len(data), data[0], data[len(data)-1])
		} else {
			buildtags.Debug("tpm debug: Unseal returned 0 bytes (empty)\n")
		}
		return data, nil
	}

	buildtags.Debug("tpm debug: unseal failed with '%s': %v\n", authName, err)
	lastErr := classifyUnsealError(err)
	if errors.Is(lastErr, ErrTPMLockout) {
		return nil, lastErr
	}

	return nil, lastErr
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
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
				Restricted:          true,
				Decrypt:             true,
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
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
				Restricted:          true,
				Decrypt:             true,
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

// ListNVIndexes lists all defined NV indexes in the TPM.
// Returns a map of NV index to NV public area bytes.
func (c *Client) ListNVIndexes() (map[uint32][]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	result := make(map[uint32][]byte)

	// Get NV capabilities to find defined NV indexes
	// TPMCapHandles with TPMHandle(0x01000000) as the first handle returns NV indexes
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      0x01000000, // Start from NV index range
		PropertyCount: 256,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get NV indices capability: %w", err)
	}

	// Parse the handles from the response
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("failed to parse handles: %w", err)
	}

	// Iterate through the handle list
	for _, handle := range handles.Handle {
		// Check if it's an NV index (handle type is 0x01 for NV index)
		if uint32(handle)&0xFF000000 == 0x01000000 {
			index := uint32(handle)
			pub, err := c.NVReadPublic(index)
			if err != nil {
				buildtags.Debug("tpm: failed to read NV public for 0x%x: %v\n", index, err)
				continue
			}
			result[index] = pub
			buildtags.Debug("tpm: found NV index 0x%x\n", index)
		}
	}

	return result, nil
}

// FindPCRLockNVIndex finds the PCRLock NV index by searching for NV indexes
// that have a PolicyAuthorizeNV policy set up.
// Returns the NV index if found, 0 if not found.
func (c *Client) FindPCRLockNVIndex() (uint32, error) {
	indexes, err := c.ListNVIndexes()
	if err != nil {
		return 0, err
	}

	// For now, return the first NV index found in the owner hierarchy
	// The pcrlock NV index should be in the range 0x01000000 - 0x01FFFFFF
	for index := range indexes {
		if index&0xFF000000 == 0x01000000 {
			buildtags.Debug("tpm: found potential PCRLock NV index: 0x%x\n", index)
			return index, nil
		}
	}

	return 0, fmt.Errorf("no PCRLock NV index found")
}

// ReadPCRValues reads the current PCR values from the TPM.
// Returns a map of PCR number to PCR value (digest).
func (c *Client) ReadPCRValues(bank HashAlgorithm, pcrs []uint) (map[uint][]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	result := make(map[uint][]byte)

	// Convert bank string to TPM algorithm
	var alg tpm2.TPMAlgID
	switch bank {
	case AlgSHA1:
		alg = tpm2.TPMAlgSHA1
	case AlgSHA256:
		alg = tpm2.TPMAlgSHA256
	case AlgSHA384:
		alg = tpm2.TPMAlgSHA384
	case AlgSHA512:
		alg = tpm2.TPMAlgSHA512
	default:
		alg = tpm2.TPMAlgSHA256
	}

	// Build PCR selection - use single TPMSPCRSelection with bitmap of all PCRs
	pcrSelectionIn := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      alg,
			PCRSelect: pcrsToBitmapInt(pcrs),
		}},
	}

	rsp, err := tpm2.PCRRead{
		PCRSelectionIn: pcrSelectionIn,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("PCRRead failed: %w", err)
	}

	// Parse the PCR values - they are in order of the selection
	// Each PCR value is a SHA256 digest (32 bytes)
	pcrIdx := 0
	for _, sel := range rsp.PCRValues.Digests {
		if pcrIdx < len(pcrs) {
			result[uint(pcrs[pcrIdx])] = sel.Buffer
			pcrIdx++
		}
	}

	return result, nil
}

// pcrsToBitmapInt converts a list of PCR indices to a PCR select bitmap (3 bytes for PCRs 0-23).
func pcrsToBitmapInt(pcrs []uint) []byte {
	bitmap := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr < 24 {
			bitmap[pcr/8] |= 1 << (pcr % 8)
		}
	}
	return bitmap
}

// ReadAllPCRValues reads all PCR values for a specific bank.
func (c *Client) ReadAllPCRValues(bank HashAlgorithm) (map[uint][]byte, error) {
	// Read PCRs 0-23
	return c.ReadPCRValues(bank, []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23})
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
	// systemd uses PBKDF2-HMAC-SHA256 with 10000 iterations
	// The output length matches SHA256 (32 bytes)
	return pbkdf2.Key([]byte(pin), salt, 10000, sha256.Size, sha256.New)
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

// computeAuthValue computes the auth value from salted PIN per systemd's approach:
// salted_pin → SHA256 → trim trailing zeros → auth value
func computeAuthValue(saltedPin []byte) []byte {
	// SHA256 hash of the salted PIN
	hash := sha256.Sum256(saltedPin)
	// Trim trailing zeros per TPM spec
	return bytes.TrimRight(hash[:], "\x00")
}

// trimAuthValue trims trailing zeros from auth value per TPM spec.
// This is used for SHA256-based auth values.
func trimAuthValue(auth []byte) []byte {
	return bytes.TrimRight(auth, "\x00")
}

// DerivePinAuthUnseal derives the auth value for unsealing when no salt is present.
// systemd's tpm2_auth_value_from_pin: PIN -> SHA256 -> trim_zeros
// Use DerivePinAuthSalted when the token has a tpm2_salt field.
func DerivePinAuthUnseal(pin string) []byte {
	// systemd's tpm2_auth_value_from_pin:
	// PIN -> SHA256 -> trim_zeros
	hash := sha256.Sum256([]byte(pin))
	return trimAuthValue(hash[:])
}

// DerivePinAuthSalted derives the auth value when a salt is present.
// systemd uses PBKDF2(pin, salt) → base64 → SHA256 → trim_zeros for both
// enrollment AND unseal when the token has a tpm2_salt field.
func DerivePinAuthSalted(pin string, salt []byte) []byte {
	// systemd's tpm2_util_pbkdf2_hmac_sha256 for enrollment:
	// PIN + Salt -> PBKDF2 -> salted_pin (32 bytes)
	// salted_pin -> base64 encode -> b64_string
	// b64_string -> SHA256 -> hash
	// hash -> trim trailing zeros -> auth_value
	pbkdf2Key := pbkdf2.Key([]byte(pin), salt, 10000, sha256.Size, sha256.New)
	b64String := base64.StdEncoding.EncodeToString(pbkdf2Key)
	return computeAuthValue([]byte(b64String))
}

// parseESYS_TR_SRK extracts the SRK handle and public area from systemd's serialized format.
// systemd's tpm2_srk format (ESYS_TR serialization):
//
//	[4-byte esys_handle][TPM2B_NAME][ESYS_TR metadata][TPM2B_PUBLIC]
//
// The ESYS_TR metadata between NAME and PUBLIC varies by tpm2-tss version.
// Typical layout observed in the wild:
//
//	[4-byte handle=0x81000001]
//	[2-byte name_size=0x0022][2-byte nameAlg=0x000b][32-byte name_digest]  (TPM2B_NAME)
//	[4-byte esys_metadata]                                                 (e.g. 0x00000001)
//	[2-byte pub_size][TPMT_PUBLIC]                                         (TPM2B_PUBLIC)
//
// Returns the extracted SRK handle and the raw TPMT_PUBLIC data (without TPM2B prefix).
func parseESYS_TR_SRK(srkData []byte) (handle uint32, publicData []byte, err error) {
	if len(srkData) < 8 {
		return 0, nil, fmt.Errorf("ESYS_TR SRK data too short: %d bytes", len(srkData))
	}

	buildtags.Debug("tpm: parsing ESYS_TR SRK format (total %d bytes)\n", len(srkData))

	offset := 0

	handle = binary.BigEndian.Uint32(srkData[offset : offset+4])
	buildtags.Debug("tpm:   ESYS_TR handle: 0x%08x\n", handle)
	offset += 4

	if handle != 0x81000001 && handle != 0x81000000 {
		buildtags.Debug("tpm:   warning: unexpected SRK handle 0x%x\n", handle)
	}

	if offset+2 > len(srkData) {
		return 0, nil, fmt.Errorf("ESYS_TR SRK data truncated")
	}

	nameSizeField := binary.BigEndian.Uint16(srkData[offset : offset+2])
	buildtags.Debug("tpm:   TPM2B_NAME size field: 0x%04x (%d)\n", nameSizeField, nameSizeField)
	offset += 2

	if nameSizeField == 0x000B || nameSizeField == 0x0004 || nameSizeField == 0x0023 {
		nameSize := int(nameSizeField)
		if offset+nameSize > len(srkData) {
			nameSize = len(srkData) - offset
		}
		offset += nameSize
		buildtags.Debug("tpm:   skipped bare name (%d bytes, alg 0x%04x)\n", nameSize, nameSizeField)
	} else {
		nameContentSize := int(nameSizeField)
		if offset+nameContentSize > len(srkData) {
			nameContentSize = len(srkData) - offset
		}
		offset += nameContentSize
		buildtags.Debug("tpm:   skipped TPM2B_NAME content (%d bytes)\n", nameContentSize)
	}

	if offset >= len(srkData) {
		return handle, nil, fmt.Errorf("no public data remaining after name")
	}

	pubOffset, pubSize := findTPM2BPublic(srkData, offset)
	if pubOffset < 0 {
		return handle, nil, fmt.Errorf("could not locate TPM2B_PUBLIC in ESYS_TR data after offset %d", offset)
	}

	if pubOffset+2+pubSize > len(srkData) {
		return handle, nil, fmt.Errorf("TPM2B_PUBLIC truncated: need %d bytes at offset %d, have %d", 2+pubSize, pubOffset, len(srkData)-pubOffset)
	}

	publicData = srkData[pubOffset+2 : pubOffset+2+pubSize]
	buildtags.Debug("tpm:   found TPM2B_PUBLIC at offset %d, size=%d, extracted TPMT_PUBLIC (%d bytes)\n", pubOffset, pubSize, len(publicData))

	return handle, publicData, nil
}

// knownTPMObjectTypes are valid TPMI_ALG_PUBLIC type values used in TPMT_PUBLIC.
var knownTPMObjectTypes = map[uint16]bool{
	0x0001: true, // TPM_ALG_RSA
	0x0008: true, // TPM_ALG_KEYEDHASH
	0x0023: true, // TPM_ALG_ECC
	0x0025: true, // TPM_ALG_SYMCIPHER
}

// findTPM2BPublic scans srkData from startOffset looking for a valid TPM2B_PUBLIC pattern.
// A valid TPM2B_PUBLIC starts with [2-byte size] where size points to data whose first
// 2 bytes are a known TPMI_ALG_PUBLIC type.
// Returns (offset of TPM2B_PUBLIC, size field value) or (-1, 0) if not found.
func findTPM2BPublic(data []byte, startOffset int) (int, int) {
	for i := startOffset; i+4 <= len(data); i++ {
		pubSize := int(binary.BigEndian.Uint16(data[i : i+2]))
		if pubSize < 2 || i+2+2 > len(data) {
			continue
		}
		objType := binary.BigEndian.Uint16(data[i+2 : i+4])
		if knownTPMObjectTypes[objType] && i+2+pubSize <= len(data) {
			return i, pubSize
		}
	}
	return -1, 0
}

// loadExternalSRK loads an SRK from public data for use as a parent in TPM2_Load.
// This handles the tpm2_srk field from systemd v255+ tokens which contains
// ESYS_TR serialized data (not raw TPMT_PUBLIC).
//
// When ESYS_TR data provides a persistent SRK handle (e.g., 0x81000001), we
// MUST use ReadPublic on that persistent handle rather than LoadExternal.
// The transient object from LoadExternal lacks proper auth properties needed
// by TPM2_Load, causing TPM_RC_AUTH_UNAVAILABLE. The persistent handle has
// the correct auth and hierarchy association.
//
// LoadExternal is only used as a fallback when no persistent handle is available
// (e.g., raw TPMT_PUBLIC data without ESYS_TR metadata).
func (c *Client) loadExternalSRK(tpm transport.TPM, publicData []byte) (tpm2.AuthHandle, func(), error) {
	buildtags.Debug("tpm: Loading SRK from tpm2_srk public data (%d bytes)\n", len(publicData))

	if len(publicData) >= 16 {
		buildtags.Debug("tpm: SRK public data hex (first 16 bytes): %x\n", publicData[:16])
	}

	loadData := publicData
	extractedHandle := uint32(0)

	if isESYS_TR_Format(publicData) {
		buildtags.Debug("tpm: detected ESYS_TR format, extracting TPMT_PUBLIC\n")
		handle, pubData, err := parseESYS_TR_SRK(publicData)
		if err != nil {
			buildtags.Debug("tpm: failed to parse ESYS_TR format: %v, trying raw format\n", err)
		} else {
			extractedHandle = handle
			loadData = pubData
			buildtags.Debug("tpm: extracted SRK handle from ESYS_TR: 0x%08x\n", handle)
		}
	}

	// When we have a persistent SRK handle from ESYS_TR data, always use
	// ReadPublic on that handle. The transient SRK from LoadExternal lacks
	// auth properties needed by TPM2_Load (causes TPM_RC_AUTH_UNAVAILABLE).
	if extractedHandle != 0 && isPersistentHandle(extractedHandle) {
		buildtags.Debug("tpm: Using persistent SRK handle 0x%08x via ReadPublic (transient LoadExternal SRK lacks auth)\n", extractedHandle)

		pubRsp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(extractedHandle)}.Execute(tpm)
		if err != nil {
			return tpm2.AuthHandle{}, nil, fmt.Errorf("ReadPublic for persistent SRK 0x%x failed: %w", extractedHandle, err)
		}

		buildtags.Debug("tpm: ReadPublic succeeded for handle 0x%08x, name: %x\n", extractedHandle, pubRsp.Name)

		srk := tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(extractedHandle),
			Name:   pubRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		}

		return srk, func() {}, nil
	}

	// Fallback: use LoadExternal for raw TPMT_PUBLIC data or transient handles
	loadCmd := tpm2.LoadExternal{
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](loadData),
		Hierarchy: tpm2.TPMRHOwner,
	}

	rsp, err := loadCmd.Execute(tpm)
	if err != nil {
		return tpm2.AuthHandle{}, nil, fmt.Errorf("LoadExternal failed: %w", err)
	}

	buildtags.Debug("tpm: SRK loaded via LoadExternal, handle: 0x%x\n", rsp.ObjectHandle)

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

// isPersistentHandle checks if a TPM handle is in the persistent handle range
// (0x81000000 - 0x81FFFFFF per TPM 2.0 Spec Part 1, Table 5).
func isPersistentHandle(handle uint32) bool {
	return handle >= 0x81000000 && handle <= 0x81FFFFFF
}

// isESYS_TR_Format checks if the SRK data appears to be in ESYS_TR serialized format.
// ESYS_TR format starts with a TPM handle (0x81XXXXXX) followed by size fields.
func isESYS_TR_Format(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	if data[0] != 0x81 {
		return false
	}

	handle := binary.BigEndian.Uint32(data[:4])
	if handle != 0x81000001 && handle != 0x81000000 {
		return false
	}

	return true
}
