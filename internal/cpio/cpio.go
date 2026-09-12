package cpio

import (
	"bytes"
	"io"
	"os"

	"github.com/cavaliergopher/cpio"
)

// svr4HeaderLen is the SVR4 ASCII header length; fields 62-94 hold
// devmajor/devminor/rmajor/rminor as 8-hex-digit groups.
const svr4HeaderLen = 110

// svr4MagicPrefix matches "070701"/"070702" header starts.
var svr4MagicPrefix = []byte("07070")

// rdevPatcher patches the device-number fields into SVR4 headers written by
// cavaliergopher/cpio v1.0.1. That library never serializes devmajor/
// devminor/rmajor/rminor (it leaves ASCII '0'), so the kernel's initramfs
// parser would create every device node as (0,0) — unusable /dev/console
// on kernels that do not auto-mount devtmpfs. It forwards everything and
// rewrites the four rdev fields on the 110-byte header write when armed.
type rdevPatcher struct {
	w            io.Writer
	major, minor uint32
	pending      bool
}

func (p *rdevPatcher) Write(data []byte) (int, error) {
	if p.pending && len(data) >= svr4HeaderLen && bytes.HasPrefix(data, svr4MagicPrefix) {
		buf := make([]byte, len(data))
		copy(buf, data)
		// Kernel initramfs parsing (init/initramfs.c) reads rmajor/rminor
		// (header[9]/[10]); write both major/minor pairs for completeness.
		writeHexField(buf[62:70], int64(p.major))
		writeHexField(buf[70:78], int64(p.minor))
		writeHexField(buf[78:86], int64(p.major))
		writeHexField(buf[86:94], int64(p.minor))
		p.pending = false
		n, err := p.w.Write(buf)
		return n, err
	}
	return p.w.Write(data)
}

// writeHexField renders v as an 8-character uppercase hex field.
func writeHexField(b []byte, v int64) {
	const hexdigits = "0123456789ABCDEF"
	for i := 7; i >= 0; i-- {
		b[i] = hexdigits[v&0xf]
		v >>= 4
	}
}

// Archive wraps CPIO writer for creating initramfs images
type Archive struct {
	writer  *cpio.Writer
	patcher *rdevPatcher
}

// NewArchive creates a new CPIO archive writer
func NewArchive(w io.Writer) *Archive {
	p := &rdevPatcher{w: w}
	return &Archive{
		writer:  cpio.NewWriter(p),
		patcher: p,
	}
}

// AddFile adds a regular file to the archive
func (a *Archive) AddFile(path string, content []byte, mode os.FileMode) error {
	hdr := &cpio.Header{
		Name: path,
		Mode: cpio.TypeReg | cpio.FileMode(mode.Perm()),
		Size: int64(len(content)),
	}

	if err := a.writer.WriteHeader(hdr); err != nil {
		return err
	}

	_, err := a.writer.Write(content)
	return err
}

// AddFileFromDisk adds a file from the host filesystem to the archive
func (a *Archive) AddFileFromDisk(srcPath, dstPath string) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	return a.AddFile(dstPath, content, info.Mode())
}

// AddDirectory adds a directory entry to the archive
func (a *Archive) AddDirectory(path string, mode os.FileMode) error {
	hdr := &cpio.Header{
		Name: path,
		Mode: cpio.TypeDir | cpio.FileMode(mode.Perm()),
	}
	return a.writer.WriteHeader(hdr)
}

// AddSymlink adds a symbolic link to the archive
func (a *Archive) AddSymlink(path, target string) error {
	hdr := &cpio.Header{
		Name:     path,
		Mode:     cpio.TypeSymlink | 0777,
		Size:     int64(len(target)),
		Linkname: target,
	}

	if err := a.writer.WriteHeader(hdr); err != nil {
		return err
	}

	_, err := a.writer.Write([]byte(target))
	return err
}

// AddDeviceNode adds a device node to the archive.
// devType should be 'c' for character device or 'b' for block device.
//
// cavaliergopher/cpio v1.0.1 never serializes the SVR4 devmajor/devminor/
// rmajor/rminor header fields, so AddDeviceNode arms the rdevPatcher with
// the device numbers before writing the header — the next 110-byte header
// write gets the fields patched in, and the kernel's initramfs parser then
// creates the node with the correct major/minor.
func (a *Archive) AddDeviceNode(path string, mode os.FileMode, devType byte, major, minor uint32) error {
	var cpioMode cpio.FileMode
	if devType == 'c' {
		cpioMode = cpio.TypeChar
	} else {
		cpioMode = cpio.TypeBlock
	}

	a.patcher.major = major
	a.patcher.minor = minor
	a.patcher.pending = true
	defer func() { a.patcher.pending = false }()

	hdr := &cpio.Header{
		Name: path,
		Mode: cpioMode | cpio.FileMode(mode.Perm()),
	}
	return a.writer.WriteHeader(hdr)
}

// Close finalizes the archive
func (a *Archive) Close() error {
	return a.writer.Close()
}
