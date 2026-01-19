package compress

import (
	"compress/gzip"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Writer wraps a compression writer
type Writer struct {
	writer io.WriteCloser
	base   io.Writer
}

// NewWriter creates a new compression writer based on the algorithm
func NewWriter(w io.Writer, algorithm string) (*Writer, error) {
	var compressor io.WriteCloser
	var err error

	switch algorithm {
	case "gzip":
		compressor, err = gzip.NewWriterLevel(w, gzip.BestSpeed)
	case "zstd":
		var enc *zstd.Encoder
		enc, err = zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
		compressor = enc
	case "none", "":
		// No compression - use a passthrough writer
		return &Writer{
			writer: &nopCloser{w},
			base:   w,
		}, nil
	default:
		compressor, err = gzip.NewWriterLevel(w, gzip.BestSpeed)
	}

	if err != nil {
		return nil, err
	}

	return &Writer{
		writer: compressor,
		base:   w,
	}, nil
}

// Write writes data to the compressor
func (w *Writer) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

// Close closes the compressor
func (w *Writer) Close() error {
	return w.writer.Close()
}

// nopCloser wraps an io.Writer to add a no-op Close method
type nopCloser struct {
	io.Writer
}

func (n *nopCloser) Close() error {
	return nil
}
