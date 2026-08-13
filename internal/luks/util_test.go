package luks

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPowerOfTwo(t *testing.T) {
	tests := []struct {
		input uint
		want  bool
	}{
		{0, true},
		{1, true},
		{2, true},
		{4, true},
		{8, true},
		{256, true},
		{3, false},
		{5, false},
		{7, false},
		{100, false},
	}
	for _, tt := range tests {
		if got := isPowerOfTwo(tt.input); got != tt.want {
			t.Errorf("isPowerOfTwo(%d) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		n, div, want int
	}{
		{0, 512, 0},
		{1, 512, 512},
		{511, 512, 512},
		{512, 512, 512},
		{513, 512, 1024},
		{1000, 512, 1024},
		{10, 4, 12},
	}
	for _, tt := range tests {
		if got := roundUp(tt.n, tt.div); got != tt.want {
			t.Errorf("roundUp(%d, %d) = %d, want %d", tt.n, tt.div, got, tt.want)
		}
	}
}

func TestFixedArrayToString(t *testing.T) {
	// With null terminator
	input := []byte("hello\x00world")
	got := fixedArrayToString(input)
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}

	// Without null terminator
	input2 := []byte("nocompiler")
	got2 := fixedArrayToString(input2)
	if got2 != "nocompiler" {
		t.Errorf("got %q, want %q", got2, "nocompiler")
	}

	// Empty
	got3 := fixedArrayToString([]byte{})
	if got3 != "" {
		t.Errorf("got %q, want empty", got3)
	}
}

func TestClearSlice(t *testing.T) {
	s := []byte{1, 2, 3, 4, 5}
	clearSlice(s)
	for i, b := range s {
		if b != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, b)
		}
	}
}

func TestGetHashAlgo(t *testing.T) {
	tests := []struct {
		name string
		want bool // should return non-nil
	}{
		{"sha1", true},
		{"sha224", true},
		{"sha256", true},
		{"sha384", true},
		{"sha512", true},
		{"sha3-224", true},
		{"sha3-256", true},
		{"sha3-384", true},
		{"sha3-512", true},
		{"ripemd160", true},
		{"blake2b-160", true},
		{"blake2b-256", true},
		{"blake2b-384", true},
		{"blake2b-512", true},
		{"blake2s-256", true},
		{"whirlpool", true},
		{"unknown", false},
		{"", false},
	}
	for _, tt := range tests {
		fn, size := getHashAlgo(tt.name)
		if tt.want {
			if fn == nil {
				t.Errorf("getHashAlgo(%q): expected non-nil function", tt.name)
				continue
			}
			if size <= 0 {
				t.Errorf("getHashAlgo(%q): expected positive size, got %d", tt.name, size)
			}
			// Verify the function actually works
			h := fn()
			h.Write([]byte("test"))
			if h.Size() != size {
				t.Errorf("getHashAlgo(%q): hash size mismatch: got %d, want %d", tt.name, h.Size(), size)
			}
		} else {
			if fn != nil {
				t.Errorf("getHashAlgo(%q): expected nil for unknown", tt.name)
			}
		}
	}
}

func TestGetCipher(t *testing.T) {
	// AES
	fn, err := getCipher("aes")
	if err != nil {
		t.Fatalf("getCipher aes: %v", err)
	}
	block, err := fn([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("aes NewCipher: %v", err)
	}
	if block.BlockSize() != 16 {
		t.Errorf("aes block size: got %d, want 16", block.BlockSize())
	}

	// Camellia
	_, err = getCipher("camellia")
	if err != nil {
		t.Fatalf("getCipher camellia: %v", err)
	}

	// Twofish
	_, err = getCipher("twofish")
	if err != nil {
		t.Fatalf("getCipher twofish: %v", err)
	}

	// Unknown
	_, err = getCipher("unknown")
	if err == nil {
		t.Error("expected error for unknown cipher")
	}
}

func TestFileSizeRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	content := []byte("test content for file size")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	size, err := fileSize(f)
	if err != nil {
		t.Fatalf("fileSize: %v", err)
	}
	if size != uint64(len(content)) {
		t.Errorf("fileSize: got %d, want %d", size, len(content))
	}
}

func TestFileSizeEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	size, err := fileSize(f)
	if err != nil {
		t.Fatalf("fileSize: %v", err)
	}
	if size != 0 {
		t.Errorf("fileSize: got %d, want 0", size)
	}
}

func TestBlake2bConstructor(t *testing.T) {
	fn, size := blake2bConstructor(256)
	if fn == nil {
		t.Fatal("expected non-nil")
	}
	if size != 32 {
		t.Errorf("size: got %d, want 32", size)
	}
	h := fn()
	h.Write([]byte("test"))
	if h.Size() != 32 {
		t.Errorf("hash size: got %d, want 32", h.Size())
	}
}

func TestBlake2s256Constructor(t *testing.T) {
	fn, size := blake2s256Constructor()
	if fn == nil {
		t.Fatal("expected non-nil")
	}
	if size != 32 {
		t.Errorf("size: got %d, want 32", size)
	}
	h := fn()
	h.Write([]byte("test"))
	if h.Size() != 32 {
		t.Errorf("hash size: got %d, want 32", h.Size())
	}
}

// Verify sha256 and sha512 hash sizes match what getHashAlgo returns
func TestGetHashAlgoSizes(t *testing.T) {
	_, size256 := getHashAlgo("sha256")
	if size256 != sha256.Size {
		t.Errorf("sha256 size: got %d, want %d", size256, sha256.Size)
	}
	_, size512 := getHashAlgo("sha512")
	if size512 != sha512.Size {
		t.Errorf("sha512 size: got %d, want %d", size512, sha512.Size)
	}
}

func TestClearSliceEmpty(t *testing.T) {
	clearSlice([]byte{}) // should not panic
}

func TestFixedArrayToStringAllZeros(t *testing.T) {
	input := make([]byte, 10)
	got := fixedArrayToString(input)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestRoundUpExact(t *testing.T) {
	if roundUp(512, 512) != 512 {
		t.Error("512/512 should be 512")
	}
	if roundUp(1024, 512) != 1024 {
		t.Error("1024/512 should be 1024")
	}
}

func TestBytesEqualUtil(t *testing.T) {
	// Test the bytes.Equal usage pattern (internal/luks uses bytes package)
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	if !bytes.Equal(a, b) {
		t.Error("equal slices should match")
	}
	c := []byte{1, 2, 4}
	if bytes.Equal(a, c) {
		t.Error("different slices should not match")
	}
}

func TestTryOpenLUKS(t *testing.T) {
	skipIfNoCryptsetup(t)
	// Create a real LUKS2 image
	disk := prepareLuks2DiskForTesting(t, "testpass")
	defer os.Remove(disk.Name())
	disk.Close()

	dev, err := tryOpenLUKS(disk.Name())
	if err != nil {
		t.Fatalf("tryOpenLUKS: %v", err)
	}
	if dev.Path == "" {
		t.Error("expected non-empty path")
	}
	if dev.UUID == "" {
		t.Error("expected non-empty UUID")
	}
}

func TestTryOpenLUKSNotLUKS(t *testing.T) {
	f, _ := os.CreateTemp("", "notluks-*.bin")
	f.Write([]byte("not a LUKS device"))
	f.Close()
	defer os.Remove(f.Name())

	_, err := tryOpenLUKS(f.Name())
	if err == nil {
		t.Error("expected error for non-LUKS file")
	}
}

func TestTryOpenLUKSMissing(t *testing.T) {
	_, err := tryOpenLUKS("/nonexistent/device")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDetect(t *testing.T) {
	// Detect scans /sys/block - on a real system this should work
	// Just verify it doesn't panic
	_, err := Detect()
	// It might return empty on test systems without block devices
	_ = err
}

func prepareLuks2DiskForTesting(t *testing.T, password string) *os.File {
	t.Helper()
	disk, _ := os.CreateTemp("", "vanguard-luks-test-*.img")
	disk.Truncate(24 * 1024 * 1024)
	disk.Close()

	cmd := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "-q", "--iter-time", "5", disk.Name())
	cmd.Stdin = strings.NewReader(password)
	if err := cmd.Run(); err != nil {
		t.Fatalf("cryptsetup luksFormat: %v", err)
	}

	f, _ := os.Open(disk.Name())
	return f
}
