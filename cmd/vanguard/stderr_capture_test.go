package main

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns
// everything fn wrote to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	w.Close()
	os.Stderr = orig
	out := <-done
	r.Close()
	return out
}
