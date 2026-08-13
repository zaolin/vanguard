package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestNewWriterNone(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "none")
	if err != nil {
		t.Fatalf("NewWriter none: %v", err)
	}
	data := []byte("hello world")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("passthrough mismatch: got %q, want %q", buf.String(), string(data))
	}
}

func TestNewWriterEmpty(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "")
	if err != nil {
		t.Fatalf("NewWriter empty: %v", err)
	}
	data := []byte("test data")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("empty algo should passthrough: got %q, want %q", buf.String(), string(data))
	}
}

func TestNewWriterGzipRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "gzip")
	if err != nil {
		t.Fatalf("NewWriter gzip: %v", err)
	}
	data := []byte("gzip roundtrip test data with some repetition. gzip roundtrip test data.")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer reader.Close()
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Errorf("gzip roundtrip mismatch: got %q, want %q", string(decompressed), string(data))
	}
}

func TestNewWriterZstdRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "zstd")
	if err != nil {
		t.Fatalf("NewWriter zstd: %v", err)
	}
	data := []byte("zstd roundtrip test data with some repetition. zstd roundtrip test data.")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	decoder, err := zstd.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer decoder.Close()
	decompressed, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Errorf("zstd roundtrip mismatch: got %q, want %q", string(decompressed), string(data))
	}
}

func TestNewWriterDefault(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "unknown-algorithm")
	if err != nil {
		t.Fatalf("NewWriter unknown: %v", err)
	}
	data := []byte("default falls back to gzip")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("unknown algorithm should fall back to gzip and produce compressed output")
	}
}
