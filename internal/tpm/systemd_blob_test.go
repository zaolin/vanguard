package tpm

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// Real systemd-tpm2 token data from a Gentoo LUKS2 + systemd-cryptenroll system.
// Source: /dev/nvme0n1p2, token type "systemd-tpm2", systemd v255+.
const (
	// tpm2-blob base64 (320 chars → 240 binary bytes)
	realTPM2BlobBase64 = "AJ4AIIopjEEpvOSjUnpjb5LIrBFRK1AIySlsKRsj5Fmsh1HfABASNFk13gHkEj891OAkcSf+vREftxNldVfd7W+ztaZdACkolDt6DMLQWzblwkOMSXZqCSZS0OO58vRmlXB6rNzTmhDo5TQyt/hAsxraPJB2veQiBMXQ9CNivc+1ASrJ226cqCsWzcA2pNdKvZSqT3DWkBS91djGPKFDAwBOAAgACwAAABIAIFv+8AXYcuFq2Lcra1mxC0t3MkvUKi6buVYnPDu2/GR+ABAAIDHjbHHPIPUyYruiwr9WAqcszu5b0FAQQykpJbES0On3"

	// tpm2_srk base64 (ESYS_TR serialized, 136 binary bytes)
	realSRKDataBase64 = "gQAAAQAiAAsWTKAHl5y8ETGw9JV9FDLb5lsFO87lpdq6iGKfrfyYaQAAAAEAWgAjAAsAAwRyAAAABgCAAEMAEAADABAAIN0EnZdrrc7pgbbvOwlDOI+ALZoZPEgXSQ8GKJtPPXPbACDEC4JDvhDzP8ClrxlsFfhJHzav65UjQbA4F2oSDyLKZQ=="

	// tpm2_salt base64 (32 binary bytes)
	realSaltBase64 = "fnPeymz6/bqr/oT6uXLkPUKiU2AULRJGis5J8x4eCOY="

	// tpm2-policy-hash (hex, 32 bytes)
	realPolicyHashHex = "5bfef005d872e16ad8b72b6b59b10b4b77324bd42a2e9bb956273c3bb6fc647e"

	// tpm2_pcrlock_nv base64 (NV public data, first 4 bytes = NV index)
	realPCRLockNVBase64 = "AaLFfgAiAAvA5UR7ifMRslVwmRO52ihgw/6GciaO08sCOpIhDfwVYQAAAAIALgGixX4ACyCEAgAICEYqud0nWMX4HHNxDAVOeZmJobupwWFtnuHo1pb7R8wCCA=="

	// The NV index extracted from tpm2_pcrlock_nv
	realNVIndex = 0x01a2c57e

	// The persistent SRK handle
	realSRKHandle = 0x81000001
)

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	return b
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func TestParseBlob_RealSystemdBlob(t *testing.T) {
	blob := mustDecodeBase64(t, realTPM2BlobBase64)

	if len(blob) != 240 {
		t.Fatalf("blob binary size: got %d, want 240", len(blob))
	}

	private, public, err := ParseBlob(blob)
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}

	if len(private) != 158 {
		t.Errorf("private size: got %d, want 158", len(private))
	}
	if len(public) != 78 {
		t.Errorf("public size: got %d, want 78", len(public))
	}

	if len(public) >= 2 {
		objType := uint16(public[0])<<8 | uint16(public[1])
		if objType != 0x0008 {
			t.Errorf("public type: got 0x%04x, want 0x0008 (KEYED_HASH)", objType)
		}
	}

	if len(public) >= 4 {
		nameAlg := uint16(public[2])<<8 | uint16(public[3])
		if nameAlg != 0x000B {
			t.Errorf("public nameAlg: got 0x%04x, want 0x000B (SHA256)", nameAlg)
		}
	}

	authPolicyOffset := 8
	if len(public) >= authPolicyOffset+2 {
		authPolicySize := uint16(public[authPolicyOffset])<<8 | uint16(public[authPolicyOffset+1])
		if authPolicySize != 32 {
			t.Errorf("authPolicy size: got %d, want 32", authPolicySize)
		}
	}

	if len(public) >= authPolicyOffset+2+32 {
		authPolicy := public[authPolicyOffset+2 : authPolicyOffset+2+32]
		expectedPolicy := mustDecodeHex(t, realPolicyHashHex)
		if !bytesEqual(authPolicy, expectedPolicy) {
			t.Errorf("authPolicy mismatch:\n  got:    %x\n  expect: %x", authPolicy, expectedPolicy)
		}
	}

	t.Logf("ParseBlob real blob: private=%d, public=%d, type=0x%04x, nameAlg=0x%04x, authPolicy matches=%v",
		len(private), len(public),
		uint16(private[0])<<8|uint16(private[1]),
		uint16(public[2])<<8|uint16(public[3]),
		bytesEqual(public[10:42], mustDecodeHex(t, realPolicyHashHex)))
}

func TestParseBlob_PublicDataNoDoubleWrap(t *testing.T) {
	blob := mustDecodeBase64(t, realTPM2BlobBase64)
	_, public, err := ParseBlob(blob)
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}

	tpm2bPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](public)
	marshaled := tpm2.Marshal(tpm2bPublic)

	if len(marshaled) < 2 {
		t.Fatalf("marshaled TPM2B_PUBLIC too short: %d bytes", len(marshaled))
	}

	marshaledSize := uint16(marshaled[0])<<8 | uint16(marshaled[1])
	if int(marshaledSize)+2 != len(marshaled) {
		t.Errorf("TPM2B_PUBLIC size mismatch: size field=%d, total=%d (expected %d)",
			marshaledSize, len(marshaled), int(marshaledSize)+2)
	}

	if int(marshaledSize) != len(public) {
		t.Errorf("TPM2B_PUBLIC double-wrap detected: size field=%d but original public=%d",
			marshaledSize, len(public))
	}

	contents, err := tpm2bPublic.Contents()
	if err != nil {
		t.Fatalf("TPM2B_PUBLIC.Contents: %v", err)
	}
	if contents.Type != tpm2.TPMAlgKeyedHash {
		t.Errorf("TPMT_PUBLIC type: got %v, want %v", contents.Type, tpm2.TPMAlgKeyedHash)
	}
	if contents.NameAlg != tpm2.TPMAlgSHA256 {
		t.Errorf("TPMT_PUBLIC nameAlg: got %v, want %v", contents.NameAlg, tpm2.TPMAlgSHA256)
	}

	t.Logf("No double-wrap: marshaled TPM2B_PUBLIC = %d bytes (size field=%d), original public = %d, type=%v, nameAlg=%v",
		len(marshaled), marshaledSize, len(public), contents.Type, contents.NameAlg)
}

func TestParseESYS_TR_SRK_RealData(t *testing.T) {
	srkData := mustDecodeBase64(t, realSRKDataBase64)

	if len(srkData) != 136 {
		t.Fatalf("SRK binary size: got %d, want 136", len(srkData))
	}

	handle, publicData, err := parseESYS_TR_SRK(srkData)
	if err != nil {
		t.Fatalf("parseESYS_TR_SRK: %v", err)
	}

	if handle != realSRKHandle {
		t.Errorf("handle: got 0x%08x, want 0x%08x", handle, realSRKHandle)
	}

	if len(publicData) == 0 {
		t.Fatal("publicData is empty")
	}

	objType := uint16(publicData[0])<<8 | uint16(publicData[1])
	if !knownTPMObjectTypes[objType] {
		t.Errorf("publicData type: 0x%04x is not a known TPM object type", objType)
	}

	tpm2bPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](publicData)
	contents, err := tpm2bPublic.Contents()
	if err != nil {
		t.Fatalf("TPM2B_PUBLIC.Contents: %v", err)
	}

	if contents.Type != tpm2.TPMAlgECC {
		t.Errorf("SRK type: got %v, want %v", contents.Type, tpm2.TPMAlgECC)
	}
	if contents.NameAlg != tpm2.TPMAlgSHA256 {
		t.Errorf("SRK nameAlg: got %v, want %v", contents.NameAlg, tpm2.TPMAlgSHA256)
	}

	t.Logf("ESYS_TR parse: handle=0x%08x, publicData=%d bytes, type=%v, nameAlg=%v",
		handle, len(publicData), contents.Type, contents.NameAlg)
}

func TestParseESYS_TR_SRK_LoadExternalCompatibility(t *testing.T) {
	srkData := mustDecodeBase64(t, realSRKDataBase64)

	_, publicData, err := parseESYS_TR_SRK(srkData)
	if err != nil {
		t.Fatalf("parseESYS_TR_SRK: %v", err)
	}

	tpm2bPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](publicData)
	marshaled := tpm2.Marshal(tpm2bPublic)

	if len(marshaled) < 4 {
		t.Fatalf("marshaled TPM2B_PUBLIC too short: %d bytes", len(marshaled))
	}

	marshaledSize := uint16(marshaled[0])<<8 | uint16(marshaled[1])
	tpmtPublicStart := 2
	tpmtPublicEnd := tpmtPublicStart + int(marshaledSize)

	if tpmtPublicEnd > len(marshaled) {
		t.Fatalf("marshaled data truncated: need %d bytes, have %d", tpmtPublicEnd, len(marshaled))
	}

	objType := uint16(marshaled[2])<<8 | uint16(marshaled[3])
	if !knownTPMObjectTypes[objType] {
		t.Errorf("after marshaling, type field is 0x%04x — not a valid TPM object type (double-wrap bug?)", objType)
	}

	t.Logf("LoadExternal compatibility: marshaled %d bytes, size field=%d, type=0x%04x",
		len(marshaled), marshaledSize, objType)
}

func TestFindTPM2BPublic_WithRealSRKData(t *testing.T) {
	srkData := mustDecodeBase64(t, realSRKDataBase64)

	offset, size := findTPM2BPublic(srkData, 40)
	if offset < 0 {
		t.Fatal("findTPM2BPublic did not find TPM2B_PUBLIC in SRK data")
	}

	if offset != 44 {
		t.Errorf("TPM2B_PUBLIC offset: got %d, want 44", offset)
	}

	if size != 90 {
		t.Errorf("TPM2B_PUBLIC size: got %d, want 90", size)
	}

	tpmtPublic := srkData[offset+2 : offset+2+size]
	objType := uint16(tpmtPublic[0])<<8 | uint16(tpmtPublic[1])
	if objType != 0x0023 {
		t.Errorf("TPMT_PUBLIC type at found offset: 0x%04x, want 0x0023 (ECC)", objType)
	}

	t.Logf("findTPM2BPublic: offset=%d, size=%d, type=0x%04x", offset, size, objType)
}

func TestSaltDerivation_RealSalt(t *testing.T) {
	salt := mustDecodeBase64(t, realSaltBase64)

	if len(salt) != 32 {
		t.Fatalf("salt size: got %d, want 32", len(salt))
	}

	auth := DerivePinAuthSalted("1234", salt)
	if len(auth) == 0 {
		t.Fatal("DerivePinAuthSalted returned empty auth value")
	}
	if auth[len(auth)-1] == 0 {
		t.Error("DerivePinAuthSalted should trim trailing zeros but last byte is 0")
	}

	authUnsalted := DerivePinAuthUnseal("1234")
	if bytesEqual(auth, authUnsalted) {
		t.Error("salted and unsalted auth values should differ with real salt")
	}

	t.Logf("Real salt auth derivation: salt=%d bytes, auth=%d bytes, first=0x%02x, last=0x%02x",
		len(salt), len(auth), auth[0], auth[len(auth)-1])
}

func TestPCRLockNVExtraction_RealData(t *testing.T) {
	nvData := mustDecodeBase64(t, realPCRLockNVBase64)

	if len(nvData) < 4 {
		t.Fatalf("NV data too short: %d bytes", len(nvData))
	}

	nvIndex := uint32(nvData[0])<<24 | uint32(nvData[1])<<16 | uint32(nvData[2])<<8 | uint32(nvData[3])
	if nvIndex != realNVIndex {
		t.Errorf("NV index: got 0x%08x, want 0x%08x", nvIndex, realNVIndex)
	}

	if nvIndex&0xFF000000 != 0x01000000 {
		t.Errorf("NV index 0x%08x not in valid owner hierarchy range", nvIndex)
	}

	t.Logf("NV index extraction: 0x%08x (valid=%v)", nvIndex, nvIndex&0xFF000000 == 0x01000000)
}