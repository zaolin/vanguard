package luks

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestDiffuseEmptyBlock(t *testing.T) {
	h := sha256.New()
	result := diffuse(nil, h)
	if len(result) != 0 {
		t.Errorf("diffuse(nil,h) length: got %d, want 0", len(result))
	}
}

func TestDiffuseSingleByte(t *testing.T) {
	h := sha256.New()
	block := []byte{0x42}
	result := diffuse(block, h)
	if len(result) == 0 {
		t.Error("diffuse with single byte should return non-empty")
	}
}

func TestAFSplitMergeRoundtripEmpty(t *testing.T) {
	h := sha256.New()
	blockSize := 16
	data := make([]byte, blockSize)
	stripes, err := afSplit(data, 3, h)
	if err != nil {
		t.Fatalf("afSplit: %v", err)
	}
	if len(stripes) != blockSize*3 {
		t.Fatalf("afSplit output length: got %d, want %d", len(stripes), blockSize*3)
	}
	result, err := afMerge(stripes, blockSize, 3, h)
	if err != nil {
		t.Fatalf("afMerge: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("afSplit/afMerge roundtrip failed for zero data")
	}
}

func TestAFSplitMergeRoundtripNonZero(t *testing.T) {
	h := sha256.New()
	blockSize := 32
	data := make([]byte, blockSize)
	for i := range data {
		data[i] = byte(i + 1)
	}
	stripes, err := afSplit(data, 4, h)
	if err != nil {
		t.Fatalf("afSplit: %v", err)
	}
	result, err := afMerge(stripes, blockSize, 4, h)
	if err != nil {
		t.Fatalf("afMerge: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("afSplit/afMerge roundtrip failed for non-zero data")
	}
}
