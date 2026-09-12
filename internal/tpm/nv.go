package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/zaolin/vanguard/init/buildtags"
)

// ErrSeedPCRMismatch indicates the seed NV read failed because the current
// PCR state does not satisfy the index authPolicy (Secure Boot state
// changed or untrusted boot). This is the ONLY condition under which
// recovery --auto-reseed may replace the seed.
var ErrSeedPCRMismatch = errors.New("TPM seed policy mismatch")

// ErrSeedReadTransient indicates the seed NV read failed for a
// non-policy reason (transport error, session creation failure, or any
// TPM response code that is not a policy/auth failure). Callers must
// treat this as retryable/diagnostic — NEVER as a reason to reseed.
var ErrSeedReadTransient = errors.New("TPM seed read failed (transient)")

// NV index constants for HOTP recovery.
const (
	// DefaultRecoverySeedNVIndex stores the HOTP seed (32 bytes).
	// Protected by PolicyRead/PolicyWrite — only accessible when the
	// correct PCR 7 state is present (anti-evil-maid protection). No
	// PolicyDelete: the index is undefined and redefined by recovery
	// --enable / --auto-reseed via owner auth.
	DefaultRecoverySeedNVIndex = 0x01C30001

	// DefaultRecoveryStateNVIndex stores the HOTP counter (8 bytes) and the
	// failed-attempt count (4 bytes): 12 bytes total. OwnerRead/OwnerWrite —
	// not secret, but must survive reboots so the counter advances and
	// brute-force attempts accumulate across boots.
	//
	// 0x01C30002 is the legacy (removed) TOTP reference-timestamp index;
	// the state index deliberately uses a new handle so an upgrade does not
	// collide with a leftover timestamp index.
	DefaultRecoveryStateNVIndex = 0x01C30003

	// SeedSize is the HOTP seed size in bytes (256-bit HMAC-SHA256 key).
	SeedSize = 32

	// CounterSize is the HOTP counter size in bytes (uint64 big-endian).
	CounterSize = 8

	// FailCountSize is the failed-attempt counter size in bytes (uint32 big-endian).
	FailCountSize = 4

	// StateNVDataSize is the total size of the recovery state NV index:
	// counter (8) + fail count (4) = 12 bytes.
	StateNVDataSize = CounterSize + FailCountSize

	// NumBranches is the number of PolicyOR branches in the seed read policy.
	// Single branch: PCR 7 only (Secure Boot state).
	// Note: PolicyOR requires at least 2 branches per TPM 2.0 spec, so with
	// a single branch we use PolicyPCR directly (no PolicyOR).
	NumBranches = 1
)

// DefineRecoveryNVSpace creates the two NV indexes for HOTP recovery:
//   - Seed index (0x01C30001): PolicyRead/PolicyWrite, authPolicy from PCR 7
//   - Timestamp index (0x01C30002): OwnerRead/OwnerWrite, no policy
//
// The seed index's authPolicy is computed from the current PCR 7 value
// (Secure Boot state) so that the seed can only be read/written when the
// correct boot chain is present. An attacker booting from a live USB
// has different PCR values and cannot access the seed.
//
// If the indexes already exist, they are undefined first.
//
// This is the FULL provisioning path (recovery --enable) — it tears down and
// recreates BOTH indexes. Atomic-reseed staging must NOT use this function:
// use DefineSeedNVIndex/WriteSeedOnly (seed-only) so the shared timestamp
// index is never touched while a replacement seed is being staged.
func (c *Client) DefineRecoveryNVSpace(seedIndex uint32, pcrValues map[int][]byte) error {
	if err := c.UndefineRecoveryNVSpace(seedIndex, nil); err != nil {
		return err
	}
	if err := c.DefineSeedNVIndex(seedIndex, pcrValues); err != nil {
		return err
	}
	return c.DefineStateNVIndex(pcrValues)
}

// DefineSeedNVIndex defines ONLY the seed NV index at seedIndex with the
// PCR-7-bound read/write policy, replacing any existing index at that
// handle. It never touches the shared state index (0x01C30003) —
// safe for atomic-reseed temp staging (nvIndex+0x100).
func (c *Client) DefineSeedNVIndex(seedIndex uint32, pcrValues map[int][]byte) error {
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

	// Undefine existing seed index at this handle if present
	if err := c.undefineSeedNVIndex(tpm, seedIndex); err != nil {
		return err
	}

	// Define the seed NV index with PolicyRead/PolicyWrite
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
	return nil
}

// DefineStateNVIndex defines ONLY the recovery state NV index (0x01C30003),
// replacing any existing index at that handle, and initializes it to
// counter=0, failCount=0.
//
// The index is protected by the SAME PolicyPCR(PCR 7) authPolicy as the seed
// (PolicyRead/PolicyWrite). Binding the counter/fail state to PCR 7 means a
// live-USB boot (different PCR state) cannot read OR reset the counter — an
// attacker cannot roll the counter back or clear the failed-attempt cap off
// the trusted boot chain.
func (c *Client) DefineStateNVIndex(pcrValues map[int][]byte) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	authPolicy, err := computeSeedReadPolicy(AlgSHA256, pcrValues)
	if err != nil {
		return fmt.Errorf("failed to compute state index policy: %w", err)
	}

	stIndex := uint32(DefaultRecoveryStateNVIndex)

	// Undefine existing state index if present
	if c.nvIndexExists(tpm, stIndex) {
		buildtags.Debug("tpm: undefining existing recovery state NV index 0x%x\n", stIndex)
		stPubRsp, stPubErr := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(stIndex),
		}.Execute(tpm)
		if stPubErr != nil {
			return fmt.Errorf("failed to read old recovery state NV public for 0x%x: %w", stIndex, stPubErr)
		}
		if _, err := (tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(stIndex), Name: stPubRsp.NVName},
		}.Execute(tpm)); err != nil {
			return fmt.Errorf("NVUndefineSpace for recovery state 0x%x: %w", stIndex, err)
		}
	}

	// Define with PolicyRead/PolicyWrite bound to PCR 7. WriteAll is required
	// because the full 12-byte state is rewritten as a unit.
	stDef := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    tpm2.TPMHandle(stIndex),
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{PolicyWrite: true, PolicyRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true, WriteAll: true},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
			DataSize:   uint16(StateNVDataSize),
		}),
	}
	if _, err := stDef.Execute(tpm); err != nil {
		return fmt.Errorf("NVDefineSpace for recovery state 0x%x: %w", stIndex, err)
	}
	buildtags.Debug("tpm: defined recovery state NV index 0x%x (size=%d, policy=%x)\n", stIndex, StateNVDataSize, authPolicy[:8])

	// Initialize counter=0, failCount=0 via the shared writer. Release the
	// connection first — WriteRecoveryState opens its own.
	_ = tpm.Close()
	if err := c.WriteRecoveryState(0, 0); err != nil {
		return fmt.Errorf("failed to initialize recovery state: %w", err)
	}
	return nil
}

// undefineSeedNVIndex undefines only the seed index at seedIndex via owner
// auth (with platform-undefine fallback for PolicyDelete indexes). Never
// touches the timestamp index.
func (c *Client) undefineSeedNVIndex(tpm transport.TPM, seedIndex uint32) error {
	if !c.nvIndexExists(tpm, seedIndex) {
		return nil
	}
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
	return nil
}

// WriteRecoveryData writes the seed and initializes the recovery state
// (counter=0, failCount=0). This is the FULL provisioning write used by
// recovery --enable. Atomic-reseed staging must use WriteSeedOnly so the
// counter state is not touched while a replacement seed is being staged.
func (c *Client) WriteRecoveryData(seedIndex uint32, seed []byte, pcrValues map[int][]byte) error {
	if err := c.WriteSeedOnly(seedIndex, seed, pcrValues); err != nil {
		return err
	}
	return c.WriteRecoveryState(0, 0)
}

// WriteSeedOnly writes ONLY the HOTP seed to the seed NV index via a policy
// session (current PCR 7 must match the index authPolicy). It never touches
// the recovery state index — safe for atomic-reseed temp staging.
func (c *Client) WriteSeedOnly(seedIndex uint32, seed []byte, pcrValues map[int][]byte) error {
	if len(seed) != SeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
	}

	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	if err := c.writeSeedWithPolicy(tpm, seedIndex, seed, pcrValues); err != nil {
		return fmt.Errorf("failed to write seed: %w", err)
	}
	buildtags.Debug("tpm: wrote seed only (seed=%d bytes, index=0x%x)\n", len(seed), seedIndex)
	return nil
}

// WriteRecoveryState persists the HOTP counter and failed-attempt count to
// the recovery state NV index using a PolicyPCR(PCR 7) session. The seed
// index is never touched. Fails if the current PCR 7 does not match the
// state index authPolicy (untrusted boot).
func (c *Client) WriteRecoveryState(counter uint64, failCount uint32) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Read current PCR 7 and build the policy session.
	pcrValues, err := c.readSeedPolicyPCRs(tpm)
	if err != nil {
		return fmt.Errorf("failed to read PCRs for state policy: %w", err)
	}
	sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return fmt.Errorf("failed to create state policy session: %w", err)
	}
	defer cleanup()
	if err := executePolicyBranch(tpm, sess, SeedReadPolicyPCRs[0], pcrValues); err != nil {
		return fmt.Errorf("failed to satisfy state write policy (PolicyPCR): %w", err)
	}

	stIndex := uint32(DefaultRecoveryStateNVIndex)
	data := make([]byte, StateNVDataSize)
	binary.BigEndian.PutUint64(data[0:CounterSize], counter)
	binary.BigEndian.PutUint32(data[CounterSize:StateNVDataSize], failCount)

	stPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(stIndex),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVReadPublic for recovery state 0x%x: %w", stIndex, err)
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(stIndex), Name: stPubRsp.NVName, Auth: sess},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(stIndex), Name: stPubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVWrite for recovery state 0x%x: %w", stIndex, err)
	}

	buildtags.Debug("tpm: wrote recovery state (counter=%d, failCount=%d)\n", counter, failCount)
	return nil
}

// ReadRecoveryState reads the HOTP counter and failed-attempt count from the
// recovery state NV index using a PolicyPCR(PCR 7) session. The seed is NOT
// read here — use ReadSeedOnly/ReadRecoveryData for the seed. Fails if the
// current PCR 7 does not match the state index authPolicy (untrusted boot).
func (c *Client) ReadRecoveryState() (counter uint64, failCount uint32, err error) {
	tpm, err := c.openTPM()
	if err != nil {
		return 0, 0, err
	}
	defer tpm.Close()

	pcrValues, err := c.readSeedPolicyPCRs(tpm)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read PCRs for state policy: %w", err)
	}
	sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create state policy session: %w", err)
	}
	defer cleanup()
	if err := executePolicyBranch(tpm, sess, SeedReadPolicyPCRs[0], pcrValues); err != nil {
		return 0, 0, fmt.Errorf("failed to satisfy state read policy (PolicyPCR): %w", err)
	}

	stIndex := uint32(DefaultRecoveryStateNVIndex)
	stPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(stIndex),
	}.Execute(tpm)
	if err != nil {
		return 0, 0, fmt.Errorf("NVReadPublic for recovery state 0x%x: %w", stIndex, err)
	}

	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(stIndex), Name: stPubRsp.NVName, Auth: sess},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(stIndex), Name: stPubRsp.NVName},
		Size:       StateNVDataSize,
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return 0, 0, fmt.Errorf("NVRead for recovery state 0x%x: %w", stIndex, err)
	}
	data := rsp.Data.Buffer
	if len(data) < StateNVDataSize {
		return 0, 0, fmt.Errorf("recovery state NV data too short: %d bytes", len(data))
	}
	counter = binary.BigEndian.Uint64(data[0:CounterSize])
	failCount = binary.BigEndian.Uint32(data[CounterSize:StateNVDataSize])
	return counter, failCount, nil
}

// ReadRecoveryData reads the HOTP seed AND the recovery state (counter +
// fail count). The seed is read via a policy session (PCR 7-bound); the
// state is read via owner auth.
func (c *Client) ReadRecoveryData(seedIndex uint32) (seed []byte, counter uint64, failCount uint32, err error) {
	counter, failCount, err = c.ReadRecoveryState()
	if err != nil {
		return nil, 0, 0, err
	}
	seed, err = c.ReadSeedOnly(seedIndex)
	if err != nil {
		return nil, 0, 0, err
	}
	return seed, counter, failCount, nil
}

// ReadSeedOnly reads the HOTP seed from the seed NV index. The seed is read
// via a policy session requiring the current PCR 7 value to match the
// enrollment-time authPolicy. If PCR 7 has changed, this fails with
// ErrSeedPCRMismatch (see readSeedWithPolicy classification).
func (c *Client) ReadSeedOnly(seedIndex uint32) ([]byte, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	seed, err := c.readSeedWithPolicy(tpm, seedIndex, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read seed: %w", err)
	}
	buildtags.Debug("tpm: read seed only (%d bytes)\n", len(seed))
	return seed, nil
}

// StateNVExists checks if the recovery state NV index is defined.
func (c *Client) StateNVExists() bool {
	tpm, err := c.openTPM()
	if err != nil {
		return false
	}
	defer tpm.Close()
	return c.nvIndexExists(tpm, uint32(DefaultRecoveryStateNVIndex))
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

// UndefineRecoveryNVSpace removes BOTH recovery NV indexes (seed + state).
// This is the full teardown used by recovery --disable/--clean and by
// DefineRecoveryNVSpace before full re-provisioning.
//
// Atomic-reseed temp cleanup must use UndefineSeedNVSpace instead —
// deleting a temp seed through this function would also destroy the
// shared state index.
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

	if err := c.undefineSeedNVIndex(tpm, seedIndex); err != nil {
		return err
	}
	return c.undefineStateNVIndex(tpm)
}

// UndefineSeedNVSpace removes ONLY the seed NV index at seedIndex. The
// recovery state index is untouched. Safe for atomic-reseed temp cleanup.
func (c *Client) UndefineSeedNVSpace(seedIndex uint32) error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()
	return c.undefineSeedNVIndex(tpm, seedIndex)
}

// undefineStateNVIndex removes the recovery state index via owner auth.
// Caller must supply an open TPM connection.
func (c *Client) undefineStateNVIndex(tpm transport.TPM) error {
	stIndex := uint32(DefaultRecoveryStateNVIndex)
	if !c.nvIndexExists(tpm, stIndex) {
		return nil
	}
	stPubRsp, stPubErr := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(stIndex),
	}.Execute(tpm)
	if stPubErr != nil {
		return fmt.Errorf("NVReadPublic for recovery state 0x%x: %w", stIndex, stPubErr)
	}
	_, err := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(stIndex), Name: stPubRsp.NVName},
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("NVUndefineSpace for recovery state 0x%x: %w", stIndex, err)
	}
	buildtags.Debug("tpm: undefined recovery state NV index 0x%x\n", stIndex)
	return nil
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
	// Distinguish genuine PCR-policy mismatches from transport/session
	// failures: a transient error must never be mistaken for "PCR 7
	// changed" (auto-reseed acts destructively on that diagnosis).
	var pcrMismatch bool
	var lastErr error

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
			// Transport/session failures are NOT PCR mismatches — they must
			// not trigger a destructive reseed. Record the error; if the
			// transport is broken, every branch records the same class of
			// error and the caller sees ErrSeedReadTransient.
			lastErr = fmt.Errorf("failed to create policy session: %w", err)
			buildtags.Debug("tpm: seed read branch %d: failed to create session: %v\n", branchIdx, err)
			continue
		}

		err = executePolicyBranch(tpm, sess, pcrSet, pcrValues)
		if err != nil {
			cleanup()
			if isPolicyMismatch(err) {
				// TPM_RC_PCR (or PCR-changed) from PolicyPCR: the session's
				// PCR digest does not match the index authPolicy — this is the
				// genuine "PCR 7 changed" signal.
				pcrMismatch = true
			} else {
				lastErr = fmt.Errorf("PolicyPCR failed: %w", err)
			}
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
			lastErr = fmt.Errorf("NVReadPublic failed: %w", err)
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
			// NVRead auth failure with a satisfied policy session is also a
			// policy-class mismatch (authPolicy not satisfied by this session).
			if isPolicyMismatch(err) || isAuthFailure(err) {
				pcrMismatch = true
			} else {
				lastErr = fmt.Errorf("NVRead failed: %w", err)
			}
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

	if pcrMismatch {
		return nil, fmt.Errorf("%w: current PCR state does not allow seed access (Secure Boot state changed or untrusted boot)", ErrSeedPCRMismatch)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrSeedReadTransient, lastErr)
	}
	return nil, fmt.Errorf("%w: no policy branch attempted", ErrSeedReadTransient)
}

// canonicalTPMRC strips the format-1 handle/parameter/session index bits
// from a raw TPM response code, mirroring go-tpm's internal isFmt1Error
// canonicalization. The TPM returns e.g. TPM_RC_POLICY_FAIL with the
// session index set (0x99D for session 1); the exported canonical constant
// is 0x9D — direct comparison would silently misclassify.
func canonicalTPMRC(rc tpm2.TPMRC) tpm2.TPMRC {
	// Mask out the index field (bits 8-11) and the rcP/rcS subject bits,
	// matching isFmt1Error: r ^= rcP / r ^= rcS, then r &= 0xFFFFF0FF.
	return rc &^ tpm2.TPMRC(0xF00) &^ tpm2.TPMRC(0x40) &^ tpm2.TPMRC(0x800)
}

// isPolicyMismatch reports whether err is a TPM policy-failure response code
// (TPM_RC_PCR from PolicyPCR, or TPM_RC_POLICY / TPM_RC_POLICY_FAIL from
// policy-authorized access). go-tpm returns TPMRC values directly as errors;
// the code may carry session/handle index bits, so compare canonically.
func isPolicyMismatch(err error) bool {
	var rc tpm2.TPMRC
	if errors.As(err, &rc) {
		rc = canonicalTPMRC(rc)
		return rc == tpm2.TPMRCPCR || rc == tpm2.TPMRCPolicy || rc == tpm2.TPMRCPolicyFail || rc == tpm2.TPMRCPCRChanged
	}
	return false
}

// isAuthFailure reports whether err is a TPM authorization failure response
// code (TPM_RC_AUTH_FAIL / TPM_RC_AUTH_TYPE / TPM_RC_AUTH_MISSING), with
// the same canonicalization as isPolicyMismatch.
func isAuthFailure(err error) bool {
	var rc tpm2.TPMRC
	if errors.As(err, &rc) {
		rc = canonicalTPMRC(rc)
		return rc == tpm2.TPMRCAuthFail || rc == tpm2.TPMRCAuthType || rc == tpm2.TPMRCAuthMissing
	}
	return false
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
