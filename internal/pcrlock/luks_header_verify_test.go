package pcrlock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeHeaderComponent(t *testing.T, variantDir, name, digestHex string) {
	t.Helper()
	data := map[string]interface{}{
		"records": []map[string]interface{}{
			{
				"pcr": 11,
				"digests": []map[string]interface{}{
					{"hashAlg": "sha256", "digest": digestHex},
				},
			},
		},
	}
	blob, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal component: %v", err)
	}
	if err := os.WriteFile(filepath.Join(variantDir, name), blob, 0644); err != nil {
		t.Fatalf("write component: %v", err)
	}
}

func TestVerifyLUKSHeaderBinding_NotBound_NoDir(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)

	res, err := VerifyLUKSHeaderBinding(path)
	if err != nil {
		t.Fatalf("VerifyLUKSHeaderBinding: %v", err)
	}
	if res.Bound {
		t.Error("expected Bound=false when component dir missing")
	}
	if res.Match {
		t.Error("expected Match=false when not bound")
	}
	if len(res.EnrolledDigests) != 0 {
		t.Errorf("expected no enrolled digests, got %v", res.EnrolledDigests)
	}
}

func TestVerifyLUKSHeaderBinding_NotBound_Masked(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	if err := MaskLUKSHeader(); err != nil {
		t.Fatalf("MaskLUKSHeader: %v", err)
	}

	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)

	res, err := VerifyLUKSHeaderBinding(path)
	if err != nil {
		t.Fatalf("VerifyLUKSHeaderBinding: %v", err)
	}
	if res.Bound {
		t.Error("expected Bound=false when masked")
	}
	if res.Match {
		t.Error("expected Match=false when masked")
	}
}

func TestVerifyLUKSHeaderBinding_Match(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)
	digest, err := computeLUKSHeaderDigest(path)
	if err != nil {
		t.Fatalf("computeLUKSHeaderDigest: %v", err)
	}
	digestHex := fmt.Sprintf("%x", digest)

	variantDir := filepath.Join(PCRLockDir, luksHeaderVariantDirName)
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeHeaderComponent(t, variantDir, "luks-header.pcrlock", digestHex)

	res, err := VerifyLUKSHeaderBinding(path)
	if err != nil {
		t.Fatalf("VerifyLUKSHeaderBinding: %v", err)
	}
	if !res.Bound {
		t.Error("expected Bound=true")
	}
	if !res.Match {
		t.Error("expected Match=true")
	}
	if res.OnDiskDigest != digestHex {
		t.Errorf("OnDiskDigest: got %s, want %s", res.OnDiskDigest, digestHex)
	}
	if len(res.EnrolledDigests) != 1 || res.EnrolledDigests[0] != digestHex {
		t.Errorf("EnrolledDigests: got %v, want [%s]", res.EnrolledDigests, digestHex)
	}
}

func TestVerifyLUKSHeaderBinding_MatchViaEventlogVariant(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	// On-disk header differs from luks-header.pcrlock but matches the
	// eventlog variant (the "policy just updated, eventlog still has old
	// hash" window — must not be reported as tampering).
	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)
	digest, err := computeLUKSHeaderDigest(path)
	if err != nil {
		t.Fatalf("computeLUKSHeaderDigest: %v", err)
	}
	onDiskHex := fmt.Sprintf("%x", digest)

	other := createTestLUKS2ImagePcrlock(t, `{"keyslots":{"0":{}}}`)
	otherDigest, err := computeLUKSHeaderDigest(other)
	if err != nil {
		t.Fatalf("computeLUKSHeaderDigest: %v", err)
	}

	variantDir := filepath.Join(PCRLockDir, luksHeaderVariantDirName)
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeHeaderComponent(t, variantDir, "luks-header.pcrlock", fmt.Sprintf("%x", otherDigest))
	writeHeaderComponent(t, variantDir, "luks-header-eventlog.pcrlock", onDiskHex)

	res, err := VerifyLUKSHeaderBinding(path)
	if err != nil {
		t.Fatalf("VerifyLUKSHeaderBinding: %v", err)
	}
	if !res.Bound {
		t.Error("expected Bound=true")
	}
	if !res.Match {
		t.Error("expected Match=true via eventlog variant")
	}
	if len(res.EnrolledDigests) != 2 {
		t.Errorf("expected 2 enrolled digests, got %v", res.EnrolledDigests)
	}
}

func TestVerifyLUKSHeaderBinding_Mismatch(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	// Enrollment captured a digest for a different header than on disk.
	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)
	other := createTestLUKS2ImagePcrlock(t, `{"keyslots":{"0":{}}}`)
	otherDigest, err := computeLUKSHeaderDigest(other)
	if err != nil {
		t.Fatalf("computeLUKSHeaderDigest: %v", err)
	}

	variantDir := filepath.Join(PCRLockDir, luksHeaderVariantDirName)
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeHeaderComponent(t, variantDir, "luks-header.pcrlock", fmt.Sprintf("%x", otherDigest))

	res, err := VerifyLUKSHeaderBinding(path)
	if err != nil {
		t.Fatalf("VerifyLUKSHeaderBinding: %v", err)
	}
	if !res.Bound {
		t.Error("expected Bound=true")
	}
	if res.Match {
		t.Error("expected Match=false for changed header")
	}
	if res.Detail == "" {
		t.Error("expected non-empty Detail")
	}
}

func TestVerifyLUKSHeaderBinding_EmptyComponent(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	path := createTestLUKS2ImagePcrlock(t, `{"keyslots":{}}`)
	variantDir := filepath.Join(PCRLockDir, luksHeaderVariantDirName)
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Component with no PCR 11 records.
	if err := os.WriteFile(filepath.Join(variantDir, "luks-header.pcrlock"), []byte(`{"records":[]}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := VerifyLUKSHeaderBinding(path)
	if err != nil {
		t.Fatalf("VerifyLUKSHeaderBinding: %v", err)
	}
	if res.Bound {
		t.Error("expected Bound=false when no digests present")
	}
	if res.Match {
		t.Error("expected Match=false")
	}
}

func TestVerifyLUKSHeaderBinding_NonLUKSDevice(t *testing.T) {
	origDir := PCRLockDir
	PCRLockDir = t.TempDir()
	defer func() { PCRLockDir = origDir }()

	variantDir := filepath.Join(PCRLockDir, luksHeaderVariantDirName)
	if err := os.MkdirAll(variantDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeHeaderComponent(t, variantDir, "luks-header.pcrlock", "0000000000000000000000000000000000000000000000000000000000000000")

	notLUKS := filepath.Join(t.TempDir(), "not-luks.img")
	if err := os.WriteFile(notLUKS, []byte("not LUKS"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := VerifyLUKSHeaderBinding(notLUKS)
	if err == nil {
		t.Error("expected error for non-LUKS device")
	}
}

func TestParseHeaderComponentDigests_SkipsOtherPCRsAndAlgs(t *testing.T) {
	data := []byte(`{"records":[
		{"pcr": 7, "digests": [{"hashAlg":"sha256","digest":"aa"}]},
		{"pcr": 11, "digests": [
			{"hashAlg":"sha1","digest":"bb"},
			{"hashAlg":"sha256","digest":"` + fmt.Sprintf("%064x", 1) + `"}
		]},
		{"pcr": 11, "digests": [{"hashAlg":"sha256","digest":"` + fmt.Sprintf("%064x", 2) + `"}]}
	]}`)
	digests, err := parseHeaderComponentDigests(data)
	if err != nil {
		t.Fatalf("parseHeaderComponentDigests: %v", err)
	}
	if len(digests) != 2 {
		t.Fatalf("expected 2 sha256 PCR 11 digests, got %d", len(digests))
	}
	want1 := make([]byte, 32)
	want1[31] = 1
	want2 := make([]byte, 32)
	want2[31] = 2
	if !bytesEqualPcrlock(digests[0], want1) || !bytesEqualPcrlock(digests[1], want2) {
		t.Errorf("digests mismatch: %x %x", digests[0], digests[1])
	}
}
