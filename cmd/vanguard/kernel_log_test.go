package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestKernelLogPrefersDmesg pins that the dmesg command is used first
// (it handles the ring buffer correctly and returns plain text).
func TestKernelLogPrefersDmesg(t *testing.T) {
	origRunner := dmesgRunner
	origReader := kmsgReader
	t.Cleanup(func() {
		dmesgRunner = origRunner
		kmsgReader = origReader
	})

	called := false
	dmesgRunner = func() ([]byte, error) {
		called = true
		return []byte("x86/tme: enabled by BIOS\n"), nil
	}
	kmsgReader = func() (string, error) {
		t.Error("kmsg fallback used although dmesg succeeded")
		return "", nil
	}

	log, err := readKernelLog()
	if err != nil {
		t.Fatalf("readKernelLog: %v", err)
	}
	if !called {
		t.Error("dmesg was not used")
	}
	if !strings.Contains(log, "tme: enabled by BIOS") {
		t.Errorf("log = %q, want the dmesg output", log)
	}
}

// TestKernelLogFallsBackToKmsg pins that a failing dmesg makes the reader
// use /dev/kmsg.
func TestKernelLogFallsBackToKmsg(t *testing.T) {
	origRunner := dmesgRunner
	origReader := kmsgReader
	t.Cleanup(func() {
		dmesgRunner = origRunner
		kmsgReader = origReader
	})

	dmesgRunner = func() ([]byte, error) { return nil, os.ErrNotExist }
	kmsgReader = func() (string, error) { return "kmsg contents\n", nil }

	log, err := readKernelLog()
	if err != nil {
		t.Fatalf("readKernelLog: %v", err)
	}
	if log != "kmsg contents\n" {
		t.Errorf("log = %q, want the kmsg output", log)
	}
}

// TestKmsgFallbackDoesNotBlock is the regression test for the hang.
//
// /dev/kmsg has no EOF: a blocking read waits until the next kernel record
// is written. os.File.Read cannot be used for it either — the Go runtime
// poller converts the EAGAIN of a non-blocking descriptor into a wait.
// The fallback therefore has to use raw syscalls, where EAGAIN surfaces
// immediately.
//
// The test drives the production reader against a FIFO that has no writer:
// a blocking read would hang forever, the non-blocking one returns at once.
func TestKmsgFallbackDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := dir + "/kmsg"
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	type result struct {
		log string
		err error
	}
	done := make(chan result, 1)
	go func() {
		log, err := readKmsg(fifo)
		done <- result{log, err}
	}()

	select {
	case res := <-done:
		// An empty FIFO is expected to yield no data; what matters is
		// that the call returns at all.
		if res.err == nil && res.log == "" {
			t.Error("empty log with nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readKmsg blocked on an empty source — the /dev/kmsg fallback would hang vanguard status")
	}
}

// TestReadKmsgReadsAvailableData drives the production read loop against a
// FIFO that carries data: the reader must return what is available and stop
// at EAGAIN instead of waiting for more.
func TestReadKmsgReadsAvailableData(t *testing.T) {
	dir := t.TempDir()
	fifo := dir + "/kmsg"
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// O_RDWR never blocks on open and keeps a writer present, so the
	// reader sees the data and then EAGAIN.
	fd, err := syscall.Open(fifo, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("cannot open FIFO: %v", err)
	}
	defer syscall.Close(fd)

	const payload = "x86/tme: enabled by BIOS\nsecond record\n"
	if _, err := syscall.Write(fd, []byte(payload)); err != nil {
		t.Fatalf("write to FIFO: %v", err)
	}

	log, err := readKmsg(fifo)
	if err != nil {
		t.Fatalf("readKmsg: %v", err)
	}
	if log != payload {
		t.Errorf("log = %q, want %q", log, payload)
	}
}

// TestReadKernelLogReportsBothFailures pins that a failing dmesg AND a
// failing /dev/kmsg are both reported, so the operator learns why the
// kernel log was unavailable.
func TestReadKernelLogReportsBothFailures(t *testing.T) {
	origRunner := dmesgRunner
	origReader := kmsgReader
	t.Cleanup(func() {
		dmesgRunner = origRunner
		kmsgReader = origReader
	})

	dmesgRunner = func() ([]byte, error) { return nil, os.ErrNotExist }
	kmsgReader = func() (string, error) { return "", os.ErrPermission }

	_, err := readKernelLog()
	if err == nil {
		t.Fatal("expected an error when both log sources fail")
	}
	msg := err.Error()
	for _, want := range []string{"dmesg", "/dev/kmsg"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}
