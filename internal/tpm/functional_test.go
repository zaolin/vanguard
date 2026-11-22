package tpm

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/zaolin/vanguard/internal/tpm/swtpmtest"
)

// TestReadIdentity prints and checks the identity the simulator reports.
func TestReadIdentity(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	id, err := client.ReadIdentity()
	if err != nil {
		t.Fatalf("ReadIdentity: %v", err)
	}
	t.Logf("manufacturer=%q vendor=%q type=%d fw=%s family=%s",
		id.ManufacturerName, id.VendorString, id.VendorTPMType, id.FirmwareVersionString(), id.Family())

	if id.ManufacturerName == "" {
		t.Error("empty manufacturer name")
	}
	if id.Family() != TPMFamilySimulator {
		t.Errorf("family = %s, want simulator for swtpm", id.Family())
	}
}

// TestPCRBanksIncludesSHA256 pins that the bank required by pcrlock is
// reported.
func TestPCRBanksIncludesSHA256(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	banks, err := client.PCRBanks()
	if err != nil {
		t.Fatalf("PCRBanks: %v", err)
	}
	t.Logf("banks: %v", banks)

	found := false
	for _, b := range banks {
		if b == "sha256" {
			found = true
		}
	}
	if !found {
		t.Errorf("no SHA-256 bank reported: %v", banks)
	}
}

// TestGetRandomSmoke runs the RNG check against the simulator.
func TestGetRandomSmoke(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if err := client.GetRandomSmoke(); err != nil {
		t.Errorf("GetRandomSmoke: %v", err)
	}
}

// TestSealUnsealRoundtrip proves the complete seal/unseal path vanguard
// depends on.
func TestSealUnsealRoundtrip(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)
	if err := client.SealUnsealRoundtrip(); err != nil {
		t.Errorf("SealUnsealRoundtrip: %v", err)
	}
}

// TestCheckNVPolicyDigest verifies the NV-contents-vs-policy check in both
// directions against a real NV index.
func TestCheckNVPolicyDigest(t *testing.T) {
	tpmTransport, cleanup := swtpmtest.Setup(t)
	defer cleanup()

	client := NewWithTransport(tpmTransport)

	const index = uint32(0x01919EA9)
	predictions := []PCRPrediction{{PCR: 7, Values: [][]byte{make([]byte, 32)}}}

	expected, err := buildSuperPCRPolicyOffline(AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("buildSuperPCRPolicyOffline: %v", err)
	}

	define := func() {
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
		if _, err := (tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
				NVIndex: tpm2.TPMHandle(index),
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					NT:         tpm2.TPMNTOrdinary,
					WriteAll:   true,
				},
				DataSize: 34,
			}),
		}).Execute(tpmTransport); err != nil {
			t.Fatalf("NVDefineSpace: %v", err)
		}
	}
	define()
	defer func() {
		_, _ = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		}.Execute(tpmTransport)
	}()

	// Write the expected digest as a TPMT_HA payload (2-byte size + digest).
	payload := append([]byte{0, 32}, expected...)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index)},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: payload},
	}).Execute(tpmTransport); err != nil {
		t.Fatalf("NVWrite: %v", err)
	}

	match, err := client.CheckNVPolicyDigest(index, AlgSHA256, predictions)
	if err != nil {
		t.Fatalf("CheckNVPolicyDigest: %v", err)
	}
	if !match {
		t.Error("the NV contents match the policy but were reported as a mismatch")
	}

	// A different prediction must now mismatch.
	other := []PCRPrediction{{PCR: 7, Values: [][]byte{bytes32(0xAB)}}}
	match, err = client.CheckNVPolicyDigest(index, AlgSHA256, other)
	if err != nil {
		t.Fatalf("CheckNVPolicyDigest (changed policy): %v", err)
	}
	if match {
		t.Error("a changed policy was reported as matching the NV contents")
	}
}
