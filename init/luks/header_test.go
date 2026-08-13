package luks

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	intpm "github.com/zaolin/vanguard/internal/tpm"
)

func skipIfNoCryptsetup(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not found")
	}
}

func prepareLuks2Disk(t *testing.T, password string) *os.File {
	t.Helper()
	disk, err := os.CreateTemp("", "vanguard-luks2-header-test-*.img")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := disk.Truncate(24 * 1024 * 1024); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	disk.Close()

	cmd := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "-q", "--iter-time", "5", disk.Name())
	cmd.Stdin = strings.NewReader(password)
	if err := cmd.Run(); err != nil {
		t.Fatalf("cryptsetup luksFormat: %v", err)
	}
	disk2, _ := os.Open(disk.Name())
	return disk2
}

func TestFindJSONEnd(t *testing.T) {
	// Valid JSON ending with }
	data := []byte(`{"keyslots":{"0":{}}}`)
	idx := findJSONEnd(data)
	if idx != len(data) {
		t.Errorf("findJSONEnd: got %d, want %d", idx, len(data))
	}

	// JSON with trailing nulls
	data2 := append([]byte(`{"config":{}}`), make([]byte, 100)...)
	idx2 := findJSONEnd(data2)
	if idx2 != 13 { // position after the last }
		t.Errorf("findJSONEnd with nulls: got %d, want 15", idx2)
	}

	// Empty data
	idx3 := findJSONEnd([]byte{})
	if idx3 != -1 {
		t.Errorf("findJSONEnd empty: got %d, want -1", idx3)
	}

	// Data without JSON
	idx4 := findJSONEnd([]byte("no json here"))
	if idx4 != -1 {
		t.Errorf("findJSONEnd no-json: got %d, want -1", idx4)
	}
}

func TestGetLUKS2Info(t *testing.T) {
	skipIfNoCryptsetup(t)
	f := prepareLuks2Disk(t, "testpass")
	defer f.Close()
	path := f.Name()
	defer os.Remove(path)

	info, err := GetLUKS2Info(path)
	if err != nil {
		t.Fatalf("GetLUKS2Info: %v", err)
	}
	if info.Version != 2 {
		t.Errorf("Version: got %d, want 2", info.Version)
	}
	if info.StorageOffset != 0x1000 {
		t.Errorf("StorageOffset: got %d, want 0x1000", info.StorageOffset)
	}
	if info.StorageEncryption == "" {
		t.Error("StorageEncryption should not be empty")
	}
	if info.HeaderSize == 0 {
		t.Error("HeaderSize should not be 0")
	}
	if info.JSONSize == 0 {
		t.Error("JSONSize should not be 0")
	}
}

func TestGetLUKS2InfoNotLUKS(t *testing.T) {
	// Create a file that's not LUKS
	f, err := os.CreateTemp("", "not-luks-*.img")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Write([]byte("this is not a LUKS header"))
	f.Close()
	defer os.Remove(f.Name())

	_, err = GetLUKS2Info(f.Name())
	if err == nil {
		t.Error("expected error for non-LUKS file")
	}
}

func TestGetLUKS2InfoMissing(t *testing.T) {
	_, err := GetLUKS2Info("/nonexistent/device")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReadDeviceRange(t *testing.T) {
	f, err := os.CreateTemp("", "readrange-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	data := []byte("0123456789ABCDEF")
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	// Read from start
	result, err := readDeviceRange(f.Name(), 0, 4)
	if err != nil {
		t.Fatalf("readDeviceRange: %v", err)
	}
	if string(result) != "0123" {
		t.Errorf("readDeviceRange(0,4): got %q, want 0123", string(result))
	}

	// Read from offset
	result2, err := readDeviceRange(f.Name(), 4, 4)
	if err != nil {
		t.Fatalf("readDeviceRange offset: %v", err)
	}
	if string(result2) != "4567" {
		t.Errorf("readDeviceRange(4,4): got %q, want 4567", string(result2))
	}
}

func TestGetBlockDeviceSize(t *testing.T) {
	f, err := os.CreateTemp("", "blocksize-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Write(make([]byte, 1024))
	f.Close()
	defer os.Remove(f.Name())

	size, err := getBlockDeviceSize(f.Name())
	if err != nil {
		t.Fatalf("getBlockDeviceSize: %v", err)
	}
	if size != 1024 {
		t.Errorf("getBlockDeviceSize: got %d, want 1024", size)
	}
}

func TestIsLUKS(t *testing.T) {
	skipIfNoCryptsetup(t)
	f := prepareLuks2Disk(t, "testpass")
	defer f.Close()
	path := f.Name()
	defer os.Remove(path)

	if !isLUKS(path) {
		t.Error("isLUKS should return true for LUKS2 image")
	}

	// Test non-LUKS file
	f2, _ := os.CreateTemp("", "notluks-*.bin")
	f2.Write([]byte("not a LUKS device"))
	f2.Close()
	defer os.Remove(f2.Name())
	if isLUKS(f2.Name()) {
		t.Error("isLUKS should return false for non-LUKS file")
	}
}

func TestIsLUKSMissing(t *testing.T) {
	if isLUKS("/nonexistent/device") {
		t.Error("isLUKS should return false for missing file")
	}
}

func TestGenerateMappedName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/dev/nvme0n1p2", "luks-nvme0n1p2"},
		{"/dev/sda3", "luks-sda3"},
		{"/dev/mapper/vg0-root", "luks-vg0-root"},
	}
	for _, tt := range tests {
		got := generateMappedName(tt.input)
		if got != tt.want {
			t.Errorf("generateMappedName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatTPMError(t *testing.T) {
	// Test with known error types
	got := formatTPMError(intpm.ErrPolicyFailed)
	if got != "TPM unlock failed" {
		t.Errorf("formatTPMError(ErrPolicyFailed): got %q", got)
	}

	got2 := formatTPMError(intpm.ErrWrongPIN)
	if got2 != "Incorrect PIN" {
		t.Errorf("formatTPMError(ErrWrongPIN): got %q", got2)
	}

	// Test with unknown error
	got3 := formatTPMError(os.ErrNotExist)
	if !strings.Contains(got3, "TPM unlock failed") {
		t.Errorf("formatTPMError(unknown): got %q, expected to contain 'TPM unlock failed'", got3)
	}
}

func TestFormatPCRList(t *testing.T) {
	tests := []struct {
		input []int
		want  string
	}{
		{[]int{7}, "7"},
		{[]int{0, 7}, "0,7"},
		{[]int{0, 4, 7}, "0,4,7"},
		{[]int{}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		got := formatPCRList(tt.input)
		if got != tt.want {
			t.Errorf("formatPCRList(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
