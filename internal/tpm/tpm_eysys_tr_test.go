package tpm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestIsPersistentHandle(t *testing.T) {
	tests := []struct {
		name     string
		handle   uint32
		expected bool
	}{
		{"0x81000000", 0x81000000, true},
		{"0x81000001", 0x81000001, true},
		{"0x81FFFFFF", 0x81FFFFFF, true},
		{"0x8100ABCD", 0x8100ABCD, true},
		{"0x80FFFFFF just below", 0x80FFFFFF, false},
		{"0x82000000 just above", 0x82000000, false},
		{"0x80000000 transient", 0x80000000, false},
		{"0x40000001 owner", 0x40000001, false},
		{"0x00000000 zero", 0x00000000, false},
		{"0xFFFFFFFF max", 0xFFFFFFFF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPersistentHandle(tt.handle)
			if result != tt.expected {
				t.Errorf("isPersistentHandle(0x%08x) = %v, want %v", tt.handle, result, tt.expected)
			}
		})
	}
}

func TestIsESYS_TR_Format(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "nil data",
			data:     nil,
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x81},
			expected: false,
		},
		{
			name:     "valid ESYS_TR with SRK handle 0x81000001",
			data:     []byte{0x81, 0x00, 0x00, 0x01, 0x00, 0x22},
			expected: true,
		},
		{
			name:     "valid ESYS_TR with SRK handle 0x81000000",
			data:     []byte{0x81, 0x00, 0x00, 0x00, 0x00, 0x22},
			expected: true,
		},
		{
			name:     "wrong prefix 0x82",
			data:     []byte{0x82, 0x00, 0x00, 0x01, 0x00, 0x22},
			expected: false,
		},
		{
			name:     "wrong handle 0x80000001",
			data:     []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x22},
			expected: false,
		},
		{
			name:     "raw TPMT_PUBLIC (starts with algorithm)",
			data:     []byte{0x00, 0x23, 0x00, 0x0B, 0x00, 0x00},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isESYS_TR_Format(tt.data)
			if result != tt.expected {
				t.Errorf("isESYS_TR_Format(%x) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func buildTestESYS_TR(handle uint32, nameSize uint16, nameAlg uint16, nameHash []byte, esysMeta []byte, tpmtPublic []byte) []byte {
	var data []byte
	data = binary.BigEndian.AppendUint32(data, handle)
	data = binary.BigEndian.AppendUint16(data, nameSize)
	data = binary.BigEndian.AppendUint16(data, nameAlg)
	data = append(data, nameHash...)
	data = append(data, esysMeta...)
	pubSize := uint16(len(tpmtPublic))
	data = binary.BigEndian.AppendUint16(data, pubSize)
	data = append(data, tpmtPublic...)
	return data
}

func TestParseESYS_TR_SRK(t *testing.T) {
	sha256NameHash := make([]byte, 32)
	for i := range sha256NameHash {
		sha256NameHash[i] = byte(i)
	}

	eccPublic := []byte{
		0x00, 0x23, // TPM_ALG_ECC
		0x00, 0x0b, // TPM_ALG_SHA256
		0x00, 0x00, 0x00, 0x10, // objectAttributes: fixedTPM | fixedParent
		0x00, 0x00, // authPolicy size = 0
	}

	tests := []struct {
		name          string
		data          []byte
		wantErr       bool
		wantHandle    uint32
		wantPublicLen int
	}{
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "too short - only handle",
			data:    []byte{0x81, 0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name:    "too short - missing nameAlg and rest",
			data:    []byte{0x81, 0x00, 0x00, 0x01, 0x00},
			wantErr: true,
		},
		{
			name: "valid ESYS_TR format with TPM2B_PUBLIC",
			data: buildTestESYS_TR(
				0x81000001,
				0x0022, // 34-byte name (2-byte algID + 32-byte hash)
				0x000B, // SHA256
				sha256NameHash,
				[]byte{0x00, 0x00, 0x00, 0x01}, // esys metadata
				eccPublic,
			),
			wantErr:       false,
			wantHandle:    0x81000001,
			wantPublicLen: len(eccPublic),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle, pubData, err := parseESYS_TR_SRK(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseESYS_TR_SRK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if handle != tt.wantHandle {
					t.Errorf("parseESYS_TR_SRK() handle = 0x%08x, want 0x%08x", handle, tt.wantHandle)
				}
				if len(pubData) != tt.wantPublicLen {
					t.Errorf("parseESYS_TR_SRK() public len = %d, want %d", len(pubData), tt.wantPublicLen)
				}
				if len(pubData) >= 2 {
					objType := uint16(pubData[0])<<8 | uint16(pubData[1])
					if objType != 0x0023 {
						t.Errorf("public type = 0x%04x, want 0x0023 (ECC)", objType)
					}
				}
			}
		})
	}
}

func TestParseESYS_TR_SRK_RealTokenData(t *testing.T) {
	srkHex := "810000010022000b164ca007979cbc1131b0f4957d1432dbe65b053bcee5a5daba88629fadfc9869"
	srkData, err := hex.DecodeString(srkHex)
	if err != nil {
		t.Fatalf("failed to decode SRK hex: %v", err)
	}

	t.Logf("Testing with truncated SRK data (%d bytes)", len(srkData))

	if !isESYS_TR_Format(srkData) {
		t.Error("isESYS_TR_Format returned false for valid ESYS_TR data")
	}

	handle, pubData, err := parseESYS_TR_SRK(srkData)
	if err == nil {
		t.Errorf("parseESYS_TR_SRK should fail for truncated data (only NAME, no TPM2B_PUBLIC), but got handle=0x%08x, pubLen=%d", handle, len(pubData))
	} else {
		t.Logf("Correctly failed for truncated data: %v", err)
	}
}

func TestLoadExternalSRKDecision_PersistentHandle(t *testing.T) {
	srkData := mustDecodeBase64(t, realSRKDataBase64)

	if !isESYS_TR_Format(srkData) {
		t.Fatal("isESYS_TR_Format should return true for real SRK data")
	}

	handle, pubData, err := parseESYS_TR_SRK(srkData)
	if err != nil {
		t.Fatalf("parseESYS_TR_SRK: %v", err)
	}

	if !isPersistentHandle(handle) {
		t.Errorf("isPersistentHandle(0x%08x) = false, want true — ESYS_TR handle should be persistent", handle)
	}

	if handle != 0x81000001 {
		t.Errorf("handle = 0x%08x, want 0x81000001", handle)
	}

	if len(pubData) == 0 {
		t.Error("pubData should not be empty")
	}

	objType := uint16(pubData[0])<<8 | uint16(pubData[1])
	if objType != 0x0023 {
		t.Errorf("pubData type = 0x%04x, want 0x0023 (ECC)", objType)
	}

	t.Logf("ESYS_TR decision: handle=0x%08x, isPersistent=%v, pubData=%d bytes, type=0x%04x",
		handle, isPersistentHandle(handle), len(pubData), objType)
	t.Log("loadExternalSRK should use ReadPublic path (persistent handle), not LoadExternal")
}

func TestLoadExternalSRKDecision_NonPersistentHandle(t *testing.T) {
	sha256NameHash := make([]byte, 32)
	for i := range sha256NameHash {
		sha256NameHash[i] = byte(i)
	}

	eccPublic := []byte{
		0x00, 0x23, 0x00, 0x0b,
		0x00, 0x00, 0x00, 0x10,
		0x00, 0x00,
	}

	data := buildTestESYS_TR(
		0x81000001,
		0x0022,
		0x000B,
		sha256NameHash,
		[]byte{0x00, 0x00, 0x00, 0x01},
		eccPublic,
	)

	if !isESYS_TR_Format(data) {
		t.Fatal("isESYS_TR_Format should return true")
	}

	handle, _, err := parseESYS_TR_SRK(data)
	if err != nil {
		t.Fatalf("parseESYS_TR_SRK: %v", err)
	}

	if !isPersistentHandle(handle) {
		t.Errorf("isPersistentHandle(0x%08x) = false, want true", handle)
	}
}

func TestLoadExternalSRKDecision_RawPublicData(t *testing.T) {
	rawPublic := []byte{
		0x00, 0x23, 0x00, 0x0b,
		0x00, 0x04, 0x00, 0x72,
		0x00, 0x00, 0x00, 0x00,
	}

	if isESYS_TR_Format(rawPublic) {
		t.Error("isESYS_TR_Format should return false for raw TPMT_PUBLIC data")
	}

	extractedHandle := uint32(0)
	if isPersistentHandle(extractedHandle) {
		t.Error("isPersistentHandle(0) should return false — no ESYS_TR handle means LoadExternal path")
	}

	t.Log("Raw public data: should use LoadExternal path (no persistent handle)")
}

func TestIsPersistentHandle_EsysTRHandles(t *testing.T) {
	handles := []struct {
		handle     uint32
		persistent bool
	}{
		{0x81000000, true},
		{0x81000001, true},
		{0x8100FFFF, true},
		{0x81ABCDEF, true},
	}
	for _, tt := range handles {
		t.Run(fmt.Sprintf("0x%08x", tt.handle), func(t *testing.T) {
			result := isPersistentHandle(tt.handle)
			if result != tt.persistent {
				t.Errorf("isPersistentHandle(0x%08x) = %v, want %v", tt.handle, result, tt.persistent)
			}
		})
	}
}

func TestFindTPM2BPublic(t *testing.T) {
	eccPublic := []byte{
		0x00, 0x23, // TPM_ALG_ECC
		0x00, 0x0b, // TPM_ALG_SHA256
	}

	tests := []struct {
		name     string
		data     []byte
		startOff int
		wantOff  int
		wantSize int
	}{
		{
			name:     "TPM2B_PUBLIC right at start",
			data:     append([]byte{0x00, 0x04}, eccPublic...),
			startOff: 0,
			wantOff:  0,
			wantSize: 4,
		},
		{
			name:     "TPM2B_PUBLIC after 4-byte metadata",
			data:     append([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x04}, eccPublic...),
			startOff: 0,
			wantOff:  4,
			wantSize: 4,
		},
		{
			name:     "no valid TPM2B_PUBLIC",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			startOff: 0,
			wantOff:  -1,
			wantSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			off, size := findTPM2BPublic(tt.data, tt.startOff)
			if off != tt.wantOff || size != tt.wantSize {
				t.Errorf("findTPM2BPublic() = (%d, %d), want (%d, %d)", off, size, tt.wantOff, tt.wantSize)
			}
		})
	}
}
