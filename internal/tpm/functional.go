package tpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/init/buildtags"
)

// PCRBanks returns the hash algorithms of the PCR banks present in the TPM.
// A missing SHA-256 bank means pcrlock cannot work at all — better to report
// that than to fail later with an opaque unseal error.
func (c *Client) PCRBanks() ([]string, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 32, // request every bank in one response
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("GetCapability(PCRs): %w", err)
	}
	if rsp.MoreData {
		// The bank list is incomplete: claiming a bank is missing would be a
		// false diagnosis, so report the enumeration problem instead.
		return nil, fmt.Errorf("PCR bank enumeration is paginated — the bank list is incomplete")
	}

	sels, err := rsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, fmt.Errorf("decode PCR banks: %w", err)
	}

	var banks []string
	for _, sel := range sels.PCRSelections {
		banks = append(banks, hashAlgorithmName(sel.Hash))
	}
	return banks, nil
}

// hashAlgorithmName renders a TPM hash algorithm as a lower-case name.
func hashAlgorithmName(alg tpm2.TPMIAlgHash) string {
	switch alg {
	case tpm2.TPMAlgSHA1:
		return "sha1"
	case tpm2.TPMAlgSHA256:
		return "sha256"
	case tpm2.TPMAlgSHA384:
		return "sha384"
	case tpm2.TPMAlgSHA512:
		return "sha512"
	default:
		return fmt.Sprintf("0x%x", uint16(alg))
	}
}

// ErrRoundtripMismatch reports that unsealing returned different bytes than
// were sealed — a genuine failure of the seal/unseal path, not a transport or
// authorization problem.
var ErrRoundtripMismatch = errors.New("seal/unseal roundtrip mismatch")

// ErrRandomIdentical reports that two consecutive GetRandom calls returned
// the same bytes — a genuinely broken RNG, not a transport problem.
var ErrRandomIdentical = errors.New("two consecutive GetRandom calls returned identical output")

// GetRandomSmoke checks that two 32-byte random reads differ.
//
// TPM2 permits GetRandom to return fewer bytes than requested, so the reads
// accumulate until 32 bytes are available. Without that, two short (or empty)
// responses could coincidentally match and look like a broken RNG — a false
// critical. An inconclusive shortfall is an error, not ErrRandomIdentical.
func (c *Client) GetRandomSmoke() error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	read32 := func() ([]byte, error) {
		var out []byte
		for attempts := 0; attempts < 4 && len(out) < 32; attempts++ {
			rsp, err := tpm2.GetRandom{BytesRequested: uint16(32 - len(out))}.Execute(tpm)
			if err != nil {
				return nil, fmt.Errorf("GetRandom: %w", err)
			}
			out = append(out, rsp.RandomBytes.Buffer...)
		}
		if len(out) < 32 {
			return nil, fmt.Errorf("GetRandom returned only %d bytes over several calls — the check is inconclusive", len(out))
		}
		return out, nil
	}

	first, err := read32()
	if err != nil {
		return err
	}
	second, err := read32()
	if err != nil {
		return err
	}

	if bytes.Equal(first, second) {
		return ErrRandomIdentical
	}
	return nil
}

// SealUnsealRoundtrip proves the TPM's seal/unseal path end to end: create a
// transient SRK, seal a TPM-generated secret with the same policy shape
// vanguard uses (PolicyAuthValue), unseal it and compare.
//
// Only transient objects are created and they are flushed afterwards — no NV
// index is touched, and the empty object auth value means no dictionary-attack
// attempt is consumed. This is the check that answers "is the TPM actually
// able to protect my disk key" rather than "does it exist".
func (c *Client) SealUnsealRoundtrip() error {
	tpm, err := c.openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	secret, err := tpm2.GetRandom{BytesRequested: 32}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("GetRandom: %w", err)
	}

	srk, srkCleanup, err := c.createSRK(tpm, "ecc")
	if err != nil {
		return fmt.Errorf("create SRK: %w", err)
	}
	defer srkCleanup()

	authPolicy, err := computePolicyAuthValueHash(make([]byte, 32))
	if err != nil {
		return err
	}

	createRsp, err := tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{},
				Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret.RandomBytes.Buffer}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				// NoDA: a failed unseal here must not consume a
				// dictionary-attack attempt. The roundtrip is a status
				// check, not an authorization attempt the user asked for.
				NoDA: true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{}),
			Unique:     tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{}),
		}),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("seal (Create): %w", err)
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    createRsp.OutPrivate,
		InPublic:     createRsp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("load sealed object: %w", err)
	}
	defer func() {
		if _, err := (tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}).Execute(tpm); err != nil {
			buildtags.Debug("tpm: flushing the roundtrip object failed: %v\n", err)
		}
	}()

	sess, sessCleanup, err := newFixedAuthPolicySession(tpm, []byte{})
	if err != nil {
		return err
	}
	defer func() {
		if err := sessCleanup(); err != nil {
			buildtags.Debug("tpm: roundtrip session cleanup failed: %v\n", err)
		}
	}()

	if _, err := (tpm2.PolicyAuthValue{PolicySession: sess.Handle()}).Execute(tpm); err != nil {
		return fmt.Errorf("PolicyAuthValue: %w", err)
	}

	unsealRsp, err := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   sess,
	}}).Execute(tpm)
	if err != nil {
		return fmt.Errorf("unseal: %w", err)
	}

	if !bytes.Equal(unsealRsp.OutData.Buffer, secret.RandomBytes.Buffer) {
		return ErrRoundtripMismatch
	}
	return nil
}

// CheckNVPolicyDigest compares the pcrlock NV index contents against the
// super-PCR policy digest computed from the policy predictions — the same
// pre-check the initrd runs before unsealing.
//
// It answers "does the TPM still hold the policy this boot needs" rather than
// merely "does the index exist". A mismatch means the index was rewritten or
// redefined since the token was sealed.
func (c *Client) CheckNVPolicyDigest(nvIndex uint32, bank HashAlgorithm, predictions []PCRPrediction) (bool, error) {
	expected, err := buildSuperPCRPolicyOffline(bank, predictions)
	if err != nil {
		return false, err
	}

	tpm, err := c.openTPM()
	if err != nil {
		return false, err
	}
	defer tpm.Close()

	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(nvIndex)},
		Size:       34,
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		return false, fmt.Errorf("NVRead 0x%x: %w", nvIndex, err)
	}

	data := rsp.Data.Buffer
	if len(data) < 2 {
		return false, fmt.Errorf("NV index 0x%x returned %d bytes, expected 34", nvIndex, len(data))
	}
	size := int(binary.BigEndian.Uint16(data[0:2]))
	if size != 32 || len(data) < 34 {
		return false, fmt.Errorf("NV index 0x%x holds an unexpected payload (size %d)", nvIndex, size)
	}

	return bytes.Equal(expected, data[2:34]), nil
}
