package swtpmtest

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestSwtpmSetup(t *testing.T) {
	tpm, cleanup := Setup(t)
	defer cleanup()

	// Verify the TPM is working by reading capabilities
	caps, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFamilyIndicator),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("GetCapability: %v", err)
	}

	props, err := caps.CapabilityData.Data.TPMProperties()
	if err != nil {
		t.Fatalf("TPMProperties: %v", err)
	}
	if len(props.TPMProperty) == 0 {
		t.Fatal("no TPM properties returned")
	}
}

func TestSwtpmNVDefineWriteRead(t *testing.T) {
	tpm, cleanup := Setup(t)
	defer cleanup()

	// Define an NV index
	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    tpm2.TPMHandle(0x01C30010),
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true, WriteAll: true},
			DataSize:   32,
		}),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("NVDefineSpace: %v", err)
	}

	// Write data (pad to DataSize)
	testData := make([]byte, 32)
	copy(testData, []byte("swtpm test data here!!!"))
	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C30010)},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: testData},
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("NVWrite: %v", err)
	}

	// Read data back
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C30010)},
		Size:       32,
		Offset:     0,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("NVRead: %v", err)
	}

	if string(rsp.Data.Buffer) != string(testData) {
		t.Errorf("data mismatch: got %q, want %q", string(rsp.Data.Buffer), string(testData))
	}

	// Undefine
	pubRsp, _ := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(0x01C30010)}.Execute(tpm)
	tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(0x01C30010), Name: pubRsp.NVName},
	}.Execute(tpm)
}
