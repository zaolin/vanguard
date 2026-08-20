package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/zaolin/vanguard/init/buildtags"
)

// ErrTimestampMissing indicates that the timestamp NV index (0x01C30002)
// does not exist on the TPM. This can happen if a previous auto-reseed
// deleted it but failed to recreate it. The seed index may still be valid.
var ErrTimestampMissing = errors.New("timestamp NV index missing")

// NV index constants for TOTP recovery.
const (
	// DefaultRecoverySeedNVIndex stores the TOTP seed (32 bytes).
	// Protected by PolicyRead/PolicyWrite/PolicyDelete — only accessible
	// when the correct PCR state is present (anti-evil-maid protection).
	DefaultRecoverySeedNVIndex = 0x01C30001

	// DefaultRecoveryTimestampNVIndex stores the reference timestamp (8 bytes).
	// Protected by OwnerRead/OwnerWrite — not secret, just needs to be
	// writable for updates at boot.
	DefaultRecoveryTimestampNVIndex = 0x01C30002

	// SeedSize is the TOTP seed size in bytes (256-bit HMAC-SHA256 key).
	SeedSize = 32

	// TimestampSize is the reference timestamp size in bytes (int64 big-endian).
	TimestampSize = 8

	// NumBranches is the number of PolicyOR branches in the seed read policy.
	// Single branch: PCR 7 only (Secure Boot state).
	// Note: PolicyOR requires at least 2 branches per TPM 2.0 spec, so with
	// a single branch we use PolicyPCR directly (no PolicyOR).
	NumBranches = 1

	// BranchDigestSize is the size of each branch digest (SHA256 = 32 bytes).
	BranchDigestSize = 32

	// TimestampNVDataSize is the total size of the timestamp NV index data.
	// It stores the reference timestamp (8 bytes) followed by the enrollment-time
	// branch digest (NumBranches * BranchDigestSize = 32 bytes), totaling 40 bytes.
	//
	// The branch digest is stored so that PolicyOR at boot time can use the
	// enrollment-time branch digest (not a current-PCR-derived one), ensuring
	// the PolicyOR result matches the authPolicy even when PCRs have changed
	// (e.g., PCR 4 after a kernel update — the single PCR 7 branch still
	// matches because Secure Boot state is stable).
	TimestampNVDataSize = TimestampSize + NumBranches*BranchDigestSize
)

// DefineRecoveryNVSpace creates the two NV indexes for TOTP recovery:
//   - Seed index (0x01C30001): PolicyRead/PolicyWrite/PolicyDelete, authPolicy = PolicyOR
//   - Timestamp index (0x01C30002): OwnerRead/OwnerWrite, no policy
//
// The seed index's authPolicy is computed from the current PCR 7 value
// (Secure Boot state) so that the seed can only be read/written when the
// correct boot chain is present. An attacker booting from a live USB
// has different PCR values and cannot access the seed.
//
// If the indexes already exist, they are undefined first.
func (c *Client) DefineRecoveryNVSpace(seedIndex uint32, pcrValues map[int][]byte) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Compute the authPolicy for the seed index from current PCR values
	authPolicy, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err != nil {
		return fmt.Errorf("failed to compute seed read policy: %w", err)
	}

	// Compute the enrollment-time branch digests so they can be stored
	// alongside the timestamp for use by PolicyOR at boot time.
	branchDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		return fmt.Errorf("failed to compute enrollment branch digests: %w", err)
	}
	if len(branchDigests) != NumBranches {
		return fmt.Errorf("expected %d branch digests, got %d", NumBranches, len(branchDigests))
	}

	// Undefine existing indexes if present
	if c.nvIndexExists(tpm, seedIndex) {
		buildtags.Debug("tpm: undefining existing seed NV index 0x%x\n", seedIndex)
		// Read the NV name first — with CONFIG_TCG_TPM2_HMAC, the kernel
		// TPM driver requires the Name for HMAC session computation.
		oldPubRsp, oldPubErr := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(seedIndex),
		}.Execute(tpm)
		if oldPubErr != nil {
			return fmt.Errorf("failed to read old seed NV public for 0x%x: %w", seedIndex, oldPubErr)
		}

		// Try owner undefine first (works if PolicyDelete is not set)
		if _, err := (tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(seedIndex), Name: oldPubRsp.NVName},
		}.Execute(tpm)); err != nil {
			// If owner undefine fails, try platform undefine special
			// (needed if PolicyDelete is set on an existing index)
			_, err2 := (tpm2.NVUndefineSpaceSpecial{
				NVIndex:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(seedIndex), Name: oldPubRsp.NVName, Auth: tpm2.PasswordAuth(nil)},
				Platform: tpm2.AuthHandle{Handle: tpm2.TPMRHPlatform, Auth: tpm2.PasswordAuth(nil)},
			}.Execute(tpm))
			if err2 != nil {
				return fmt.Errorf("failed to undefine existing seed NV index 0x%x: owner=%v platform=%v", seedIndex, err, err2)
			}
		}
	}

	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	if c.nvIndexExists(tpm, tsIndex) {
		buildtags.Debug("tpm: undefining existing timestamp NV index 0x%x\n", tsIndex)
		tsPubRsp, tsPubErr := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(tsIndex),
		}.Execute(tpm)
		if tsPubErr != nil {
			return fmt.Errorf("failed to read old timestamp NV public for 0x%x: %w", tsIndex, tsPubErr)
		}
		if _, err := (tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		}.Execute(tpm)); err != nil {
			return fmt.Errorf("NVUndefineSpace for timestamp 0x%x: %w", tsIndex, err)
		}
	}

	// Define the seed NV index with PolicyRead/PolicyWrite/PolicyDelete
	seedDef := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(seedIndex),
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				PolicyWrite: true,
				PolicyRead:  true,
				NT:          tpm2.TPMNTOrdinary,
				NoDA:        true,
				WriteAll:    true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
			DataSize:   uint16(SeedSize),
		}),
	}
	if _, err := seedDef.Execute(tpm); err != nil {
		return fmt.Errorf("NVDefineSpace for seed 0x%x: %w", seedIndex, err)
	}
	buildtags.Debug("tpm: defined seed NV index 0x%x (size=%d, policy=%x)\n", seedIndex, SeedSize, authPolicy[:8])

	// Define the timestamp NV index with OwnerRead/OwnerWrite (no policy).
	// This index stores the reference timestamp (8 bytes) and the enrollment-time
	// branch digests (96 bytes) used by PolicyOR at boot time.
	tsDef := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(tsIndex),
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				NT:         tpm2.TPMNTOrdinary,
				NoDA:       true,
				WriteAll:   true,
			},
			DataSize: uint16(TimestampNVDataSize),
		}),
	}
	if _, err := tsDef.Execute(tpm); err != nil {
		return fmt.Errorf("NVDefineSpace for timestamp 0x%x: %w", tsIndex, err)
	}
	buildtags.Debug("tpm: defined timestamp NV index 0x%x (size=%d)\n", tsIndex, TimestampNVDataSize)

	// Write the enrollment-time branch digests to the timestamp NV index
	// (timestamp will be written separately by WriteRecoveryData).
	tsPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(tsIndex),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVReadPublic for timestamp 0x%x: %w", tsIndex, err)
	}
	tsData := make([]byte, TimestampNVDataSize)
	// Timestamp is zero-filled for now; WriteRecoveryData will overwrite it.
	// Branch digests are packed after the timestamp.
	for i, bd := range branchDigests {
		copy(tsData[TimestampSize+i*BranchDigestSize:], bd)
	}
	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: tsData},
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVWrite for enrollment branch digests 0x%x: %w", tsIndex, err)
	}
	buildtags.Debug("tpm: wrote enrollment branch digests to timestamp NV index\n")

	return nil
}

// WriteRecoveryData writes the TOTP seed and reference timestamp to the NV indexes.
// The seed is written via a policy session (PolicyPCR + PolicyOR), requiring
// the current PCR values to match the authPolicy. The timestamp is written
// via owner auth (no policy needed).
func (c *Client) WriteRecoveryData(seedIndex uint32, seed []byte, refTimestamp int64, pcrValues map[int][]byte) error {
	if len(seed) != SeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
	}

	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Write the seed via policy session
	if err := c.writeSeedWithPolicy(tpm, seedIndex, seed, pcrValues); err != nil {
		return fmt.Errorf("failed to write seed: %w", err)
	}

	// Write the timestamp via owner auth.
	// The timestamp NV index also stores the enrollment-time branch digests
	// (written by DefineRecoveryNVSpace). We only overwrite the timestamp
	// portion here, preserving the branch digests.
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	tsData := make([]byte, TimestampNVDataSize)
	binary.BigEndian.PutUint64(tsData, uint64(refTimestamp))

	// Copy enrollment branch digests into the data buffer so the write
	// preserves them (NVWrite replaces the entire index data).
	branchDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		return fmt.Errorf("failed to compute branch digests for timestamp write: %w", err)
	}
	for i, bd := range branchDigests {
		copy(tsData[TimestampSize+i*BranchDigestSize:], bd)
	}

	tsPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(tsIndex),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVReadPublic for timestamp 0x%x: %w", tsIndex, err)
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: tsData},
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVWrite for timestamp 0x%x: %w", tsIndex, err)
	}

	buildtags.Debug("tpm: wrote recovery data (seed=%d bytes, timestamp=%d, branch_digests=%d)\n", len(seed), refTimestamp, len(branchDigests))
	return nil
}

// ReadRecoveryData reads the TOTP seed, reference timestamp, and enrollment-time
// branch digests from the NV indexes. The seed is read via a policy session
// (tries each PolicyOR branch in turn). The timestamp and branch digests are
// read via owner auth.
//
// Returns the 32-byte seed, the reference Unix timestamp, and the enrollment-time
// branch digests (used by PolicyOR at boot time).
func (c *Client) ReadRecoveryData(seedIndex uint32) (seed []byte, refTimestamp int64, branchDigests [][]byte, err error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, 0, nil, err
	}
	defer tpm.Close()

	// Read the timestamp and branch digests FIRST (via owner auth, no policy needed).
	// The branch digests are needed by readSeedWithPolicy for PolicyOR.
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	tsPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(tsIndex),
	}.Execute(tpm)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("NVReadPublic for timestamp 0x%x: %w", tsIndex, err)
	}

	tsRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		Size:       TimestampNVDataSize,
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("NVRead for timestamp 0x%x: %w", tsIndex, err)
	}

	tsData := tsRsp.Data.Buffer
	if len(tsData) >= TimestampSize {
		refTimestamp = int64(binary.BigEndian.Uint64(tsData[0:TimestampSize]))
	}

	// Extract enrollment-time branch digests
	branchDigests = make([][]byte, 0, NumBranches)
	for i := 0; i < NumBranches; i++ {
		start := TimestampSize + i*BranchDigestSize
		end := start + BranchDigestSize
		if len(tsData) >= end {
			bd := make([]byte, BranchDigestSize)
			copy(bd, tsData[start:end])
			branchDigests = append(branchDigests, bd)
		}
	}

	if len(branchDigests) != NumBranches {
		return nil, 0, nil, fmt.Errorf("expected %d branch digests in timestamp NV, got %d (index may need re-enrollment)", NumBranches, len(branchDigests))
	}

	buildtags.Debug("tpm: read enrollment branch digests from timestamp NV index (%d branches)\n", len(branchDigests))

	// Read the seed via policy session, using the stored enrollment branch digests
	seed, err = c.readSeedWithPolicy(tpm, seedIndex, branchDigests)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to read seed: %w", err)
	}

	buildtags.Debug("tpm: read recovery data (seed=%d bytes, timestamp=%d)\n", len(seed), refTimestamp)
	return seed, refTimestamp, branchDigests, nil
}

// ReadSeedOnly reads the TOTP seed from the seed NV index WITHOUT requiring
// the timestamp NV index. This is used when the timestamp index is missing
// (e.g., after a failed auto-reseed) but the seed may still be readable.
//
// The seed is read via a policy session requiring the current PCR 7 value
// to match the enrollment-time authPolicy. If PCR 7 has changed, this will
// fail just like ReadRecoveryData.
//
// Returns only the seed (no timestamp or branch digests).
func (c *Client) ReadSeedOnly(seedIndex uint32) ([]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// readSeedWithPolicy ignores enrollmentBranchDigests with single-branch
	// policy (line 490: _ = enrollmentBranchDigests). It reads current PCR 7
	// values directly and uses PolicyPCR. So we can pass nil.
	seed, err := c.readSeedWithPolicy(tpm, seedIndex, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read seed: %w", err)
	}

	buildtags.Debug("tpm: read seed only (%d bytes, timestamp skipped)\n", len(seed))
	return seed, nil
}

// RecreateTimestampOnly recreates the timestamp NV index (0x01C30002) if it
// is missing, without touching the seed index. This is used by auto-reseed
// when the seed is still readable (PCR 7 matches) but the timestamp index
// was lost (e.g., from a previous failed reseed).
//
// The timestamp is set to the current time, and the branch digests are
// recomputed from the current PCR 7 values.
func (c *Client) RecreateTimestampOnly(pcrValues map[int][]byte) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)

	// Check if timestamp index already exists
	if c.nvIndexExists(tpm, tsIndex) {
		buildtags.Debug("tpm: timestamp NV index 0x%x already exists, skipping recreation\n", tsIndex)
		return nil
	}

	// Define the timestamp NV index with OwnerRead/OwnerWrite
	tsDef := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    tpm2.TPMHandle(tsIndex),
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true},
			DataSize:   uint16(TimestampNVDataSize),
		}),
	}
	if _, err := tsDef.Execute(tpm); err != nil {
		return fmt.Errorf("failed to define timestamp NV index 0x%x: %w", tsIndex, err)
	}

	// Write the timestamp data: current timestamp + branch digests
	tsData := make([]byte, TimestampNVDataSize)
	binary.BigEndian.PutUint64(tsData, uint64(time.Now().Unix()))

	branchDigests, err := computeAllBranchDigests(pcrValues)
	if err != nil {
		return fmt.Errorf("failed to compute branch digests: %w", err)
	}
	for i, bd := range branchDigests {
		copy(tsData[TimestampSize+i*BranchDigestSize:], bd)
	}

	tsPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(tsIndex),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVReadPublic for new timestamp 0x%x: %w", tsIndex, err)
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: tsData},
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVWrite for timestamp 0x%x: %w", tsIndex, err)
	}

	buildtags.Debug("tpm: recreated timestamp NV index 0x%x\n", tsIndex)
	return nil
}

// TimestampNVExists checks if the timestamp NV index is defined.
func (c *Client) TimestampNVExists() bool {
	tpm, err := c.openTPM()
	if err != nil {
		return false
	}
	defer tpm.Close()
	return c.nvIndexExists(tpm, uint32(DefaultRecoveryTimestampNVIndex))
}

// RecoveryNVExists checks if the seed NV index is defined.
func (c *Client) RecoveryNVExists(seedIndex uint32) bool {
	tpm, err := c.openTPM()
	if err != nil {
		return false
	}
	defer tpm.Close()
	return c.nvIndexExists(tpm, seedIndex)
}

// UndefineRecoveryNVSpace removes both recovery NV indexes.
// The seed index uses PolicyRead/PolicyWrite (no PolicyDelete), so it can
// be undefined via NVUndefineSpace with owner auth. The timestamp index
// also uses NVUndefineSpace with owner auth.
//
// Note: Without PolicyDelete, an attacker with owner auth can undefine the
// seed index (DoS). However, they cannot read or write the seed without
// satisfying the PCR-bound authPolicy. The undefine is a denial-of-service
// only, not a secret extraction.
func (c *Client) UndefineRecoveryNVSpace(seedIndex uint32, pcrValues map[int][]byte) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Undefine the seed index via NVUndefineSpace (owner auth)
	// Read the NV name first — with CONFIG_TCG_TPM2_HMAC, the kernel
	// TPM driver requires the Name for HMAC session computation.
	if c.nvIndexExists(tpm, seedIndex) {
		pubRsp, err := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(seedIndex),
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("NVReadPublic for seed 0x%x: %w", seedIndex, err)
		}

		_, err = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(seedIndex), Name: pubRsp.NVName},
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("NVUndefineSpace for seed 0x%x: %w", seedIndex, err)
		}
		buildtags.Debug("tpm: undefined seed NV index 0x%x\n", seedIndex)
	}

	// Undefine the timestamp index via NVUndefineSpace (owner auth only)
	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)
	if c.nvIndexExists(tpm, tsIndex) {
		tsPubRsp, tsPubErr := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(tsIndex),
		}.Execute(tpm)
		if tsPubErr != nil {
			return fmt.Errorf("NVReadPublic for timestamp 0x%x: %w", tsIndex, tsPubErr)
		}
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("NVUndefineSpace for timestamp 0x%x: %w", tsIndex, err)
		}
		buildtags.Debug("tpm: undefined timestamp NV index 0x%x\n", tsIndex)
	}

	return nil
}

// UpdateRecoveryTimestamp updates only the reference timestamp in the NV index,
// keeping the existing branch digests. Called after a successful boot to keep the
// timestamp fresh for RTC drift detection on the next boot.
func (c *Client) UpdateRecoveryTimestamp(refTimestamp int64) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	tsIndex := uint32(DefaultRecoveryTimestampNVIndex)

	// Read the existing data to preserve the branch digests
	tsPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(tsIndex),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVReadPublic for timestamp: %w", err)
	}

	existingRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		Size:       TimestampNVDataSize,
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVRead for existing timestamp data: %w", err)
	}

	// Build the new data: new timestamp + preserved branch digests
	tsData := make([]byte, TimestampNVDataSize)
	binary.BigEndian.PutUint64(tsData, uint64(refTimestamp))
	// Copy the branch digests from the existing data
	if len(existingRsp.Data.Buffer) >= TimestampNVDataSize {
		copy(tsData[TimestampSize:], existingRsp.Data.Buffer[TimestampSize:])
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tsIndex), Name: tsPubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: tsData},
		Offset:     0,
	}.Execute(tpm)
	return err
}

// --- Internal helpers for policy session-based NV access ---

// writeSeedWithPolicy writes the seed to the NV index via a policy session.
// Creates a policy session, executes PolicyPCR (single branch, no PolicyOR),
// then NVWrite.
func (c *Client) writeSeedWithPolicy(tpm transport.TPM, seedIndex uint32, seed []byte, pcrValues map[int][]byte) error {
	sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return fmt.Errorf("failed to create policy session: %w", err)
	}
	defer cleanup()

	if err := executePolicyBranch(tpm, sess, SeedReadPolicyPCRs[0], pcrValues); err != nil {
		return fmt.Errorf("failed to satisfy write policy (PolicyPCR): %w", err)
	}

	// Read the NV name for the NamedHandle
	pubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(seedIndex),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVReadPublic for seed 0x%x: %w", seedIndex, err)
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(seedIndex), Name: pubRsp.NVName, Auth: sess},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(seedIndex), Name: pubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: seed},
		Offset:     0,
	}.Execute(tpm)
	return err
}

// readSeedWithPolicy reads the seed from the NV index via a policy session.
// With a single-branch policy (PCR 7 only), this is just PolicyPCR + NVRead.
// No PolicyOR is needed (the TPM requires at least 2 branches for PolicyOR).
//
// The enrollmentBranchDigests parameter is kept for API compatibility but
// is not used with the single-branch policy — the session digest after
// PolicyPCR directly matches the authPolicy (which is just the PolicyPCR
// digest, no PolicyOR wrapping).
func (c *Client) readSeedWithPolicy(tpm transport.TPM, seedIndex uint32, enrollmentBranchDigests [][]byte) ([]byte, error) {
	_ = enrollmentBranchDigests // not used with single-branch policy

	// Read current PCR values needed for the policy
	pcrValues, err := c.readSeedPolicyPCRs(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs for seed policy: %w", err)
	}

	// Single branch: PolicyPCR for PCR 7, then NVRead
	for branchIdx, pcrSet := range SeedReadPolicyPCRs {
		// Check if all required PCRs are available
		missing := false
		for _, pcr := range pcrSet {
			if _, ok := pcrValues[pcr]; !ok {
				missing = true
				break
			}
		}
		if missing {
			buildtags.Debug("tpm: seed read branch %d skipped (missing PCRs %v)\n", branchIdx, pcrSet)
			continue
		}

		sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			buildtags.Debug("tpm: seed read branch %d: failed to create session: %v\n", branchIdx, err)
			continue
		}

		err = executePolicyBranch(tpm, sess, pcrSet, pcrValues)
		if err != nil {
			cleanup()
			buildtags.Debug("tpm: seed read branch %d (PCRs %v): PolicyPCR failed: %v\n", branchIdx, pcrSet, err)
			continue
		}

		// With single-branch policy, no PolicyOR needed — the session digest
		// after PolicyPCR directly matches the authPolicy.

		// Read the seed via NVRead with the policy session
		pubRsp, err := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(seedIndex),
		}.Execute(tpm)
		if err != nil {
			cleanup()
			buildtags.Debug("tpm: seed read branch %d: NVReadPublic failed: %v\n", branchIdx, err)
			continue
		}

		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(seedIndex), Name: pubRsp.NVName, Auth: sess},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(seedIndex), Name: pubRsp.NVName},
			Size:       SeedSize,
			Offset:     0,
		}.Execute(tpm)
		cleanup()
		if err != nil {
			buildtags.Debug("tpm: seed read branch %d: NVRead failed: %v\n", branchIdx, err)
			continue
		}

		data := rsp.Data.Buffer
		if len(data) < SeedSize {
			return nil, fmt.Errorf("seed data too short: got %d, want %d", len(data), SeedSize)
		}

		seed := make([]byte, SeedSize)
		copy(seed, data[0:SeedSize])
		buildtags.Debug("tpm: seed read succeeded via branch %d (PCRs %v)\n", branchIdx, pcrSet)
		return seed, nil
	}

	return nil, fmt.Errorf("no policy branch matched — current PCR state does not allow seed access (possible tampering or untrusted boot)")
}

// readSeedPolicyPCRs reads the PCR values needed for the seed read policy
// (PCR 7 in the SHA256 bank — single-branch policy).
func (c *Client) readSeedPolicyPCRs(tpm transport.TPM) (map[int][]byte, error) {
	requiredPCRs := []int{7}
	result := make(map[int][]byte)

	for _, pcr := range requiredPCRs {
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: pcrsToBitmap([]int{pcr}),
			}},
		}
		rsp, err := tpm2.PCRRead{PCRSelectionIn: sel}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("PCRRead for PCR %d: %w", pcr, err)
		}
		if len(rsp.PCRValues.Digests) > 0 {
			result[pcr] = rsp.PCRValues.Digests[0].Buffer
		}
	}

	return result, nil
}

// executePolicyBranch executes a single PolicyPCR command on the session
// for the given PCR set, using the current PCR values from the TPM.
func executePolicyBranch(tpm transport.TPM, sess tpm2.Session, pcrSet []int, pcrValues map[int][]byte) error {
	sel := buildPCRLSelection(AlgSHA256, pcrSet)
	_, err := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{},
		Pcrs:          sel,
	}.Execute(tpm)
	return err
}

// computeAllBranchDigests computes the offline digest for each policy branch.
// With the single-branch design, this returns one digest (PolicyPCR for PCR 7).
func computeAllBranchDigests(pcrValues map[int][]byte) ([][]byte, error) {
	var digests [][]byte
	for _, pcrSet := range SeedReadPolicyPCRs {
		pcrDigest, err := computePCRDigest(AlgSHA256, pcrValues, pcrSet)
		if err != nil {
			return nil, err
		}
		sel := buildPCRLSelection(AlgSHA256, pcrSet)
		branchDigest, err := computePolicyPCRHash(AlgSHA256, nil, pcrDigest, sel)
		if err != nil {
			return nil, err
		}
		digests = append(digests, branchDigest)
	}
	return digests, nil
}

// nvIndexExists checks if an NV index is defined on the TPM.
func (c *Client) nvIndexExists(tpm transport.TPM, index uint32) bool {
	_, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(tpm)
	return err == nil
}

// convertToTPM2BDigests converts a slice of byte slices to TPMLDigest.
func convertToTPM2BDigests(digests [][]byte) []tpm2.TPM2BDigest {
	result := make([]tpm2.TPM2BDigest, len(digests))
	for i, d := range digests {
		result[i] = tpm2.TPM2BDigest{Buffer: d}
	}
	return result
}

// CurrentTimestamp returns the current Unix timestamp.
func CurrentTimestamp() int64 {
	return time.Now().Unix()
}
