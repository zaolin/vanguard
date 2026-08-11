package gpt

import (
	"encoding/binary"
	"testing"
)

func TestParseGUID(t *testing.T) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], 0xE843DCC3)
	binary.LittleEndian.PutUint16(b[4:6], 0x7C53)
	binary.LittleEndian.PutUint16(b[6:8], 0x4E5C)
	b[8] = 0x9D
	b[9] = 0x6E
	b[10] = 0x9E
	b[11] = 0x6E
	b[12] = 0x0F
	b[13] = 0x1E
	b[14] = 0x4E
	b[15] = 0x5C

	got := parseGUID(b)
	want := "e843dcc3-7c53-4e5c-9d6e-9e6e0f1e4e5c"
	if got != want {
		t.Errorf("parseGUID: got %s, want %s", got, want)
	}
}

func TestParseGUIDTooShort(t *testing.T) {
	got := parseGUID([]byte{1, 2, 3})
	if got != "" {
		t.Errorf("parseGUID short: got %s, want empty", got)
	}
}

func TestParseUTF16Name(t *testing.T) {
	b := []byte{0x45, 0x00, 0x46, 0x00, 0x49, 0x00, 0x00, 0x00}
	got := parseUTF16Name(b)
	if got != "EFI" {
		t.Errorf("parseUTF16Name: got %s, want EFI", got)
	}
}

func TestParseUTF16NameEmpty(t *testing.T) {
	b := []byte{0x00, 0x00}
	got := parseUTF16Name(b)
	if got != "" {
		t.Errorf("parseUTF16Name empty: got %s, want empty", got)
	}
}

func TestParseUTF16NameNoNull(t *testing.T) {
	b := []byte{0x41, 0x00, 0x42, 0x00}
	got := parseUTF16Name(b)
	if got != "AB" {
		t.Errorf("parseUTF16Name no null: got %s, want AB", got)
	}
}

func TestFindPartitionByType(t *testing.T) {
	partitions := []Partition{
		{Number: 1, TypeGUID: "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"},
		{Number: 2, TypeGUID: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"},
	}
	p := FindPartitionByType(partitions, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
	if p == nil {
		t.Fatal("expected to find ESP partition")
	}
	if p.Number != 2 {
		t.Errorf("Number: got %d, want 2", p.Number)
	}
}

func TestFindPartitionByTypeNotFound(t *testing.T) {
	partitions := []Partition{
		{Number: 1, TypeGUID: "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"},
	}
	p := FindPartitionByType(partitions, "nonexistent-guid")
	if p != nil {
		t.Error("expected nil for not found")
	}
}

func TestFindAllPartitionsByType(t *testing.T) {
	guid := "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
	partitions := []Partition{
		{Number: 1, TypeGUID: guid},
		{Number: 2, TypeGUID: "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"},
		{Number: 3, TypeGUID: guid},
	}
	result := FindAllPartitionsByType(partitions, guid)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0].Number != 1 {
		t.Errorf("result[0].Number: got %d", result[0].Number)
	}
	if result[1].Number != 3 {
		t.Errorf("result[1].Number: got %d", result[1].Number)
	}
}

func TestFindAllPartitionsByTypeNone(t *testing.T) {
	partitions := []Partition{
		{Number: 1, TypeGUID: "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"},
	}
	result := FindAllPartitionsByType(partitions, "nonexistent")
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

func TestGetPartitionDeviceNVMe(t *testing.T) {
	got := GetPartitionDevice("/dev/nvme0n1", 2)
	if got != "/dev/nvme0n1p2" {
		t.Errorf("got %s, want /dev/nvme0n1p2", got)
	}
}

func TestGetPartitionDeviceMMC(t *testing.T) {
	got := GetPartitionDevice("/dev/mmcblk0", 1)
	if got != "/dev/mmcblk0p1" {
		t.Errorf("got %s, want /dev/mmcblk0p1", got)
	}
}

func TestGetPartitionDeviceSDA(t *testing.T) {
	got := GetPartitionDevice("/dev/sda", 1)
	if got != "/dev/sda1" {
		t.Errorf("got %s, want /dev/sda1", got)
	}
}

func TestGetPartitionDeviceLoop(t *testing.T) {
	got := GetPartitionDevice("/dev/loop0", 3)
	if got != "/dev/loop0p3" {
		t.Errorf("got %s, want /dev/loop0p3", got)
	}
}

func TestIsGPTAutoEnabled(t *testing.T) {
	_ = IsGPTAutoEnabled()
}