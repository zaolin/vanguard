package cpio

import (
	"io"
	"os"

	"github.com/cavaliergopher/cpio"
)

// Archive wraps CPIO writer for creating initramfs images
type Archive struct {
	writer *cpio.Writer
}

// NewArchive creates a new CPIO archive writer
func NewArchive(w io.Writer) *Archive {
	return &Archive{
		writer: cpio.NewWriter(w),
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

// AddDeviceNode adds a device node to the archive
// devType should be 'c' for character device or 'b' for block device
func (a *Archive) AddDeviceNode(path string, mode os.FileMode, devType byte, major, minor uint32) error {
	var cpioMode cpio.FileMode
	if devType == 'c' {
		cpioMode = cpio.TypeChar
	} else {
		cpioMode = cpio.TypeBlock
	}

	// Device ID encodes major/minor: (major << 8) | minor
	devID := int((major << 8) | minor)

	hdr := &cpio.Header{
		Name:     path,
		Mode:     cpioMode | cpio.FileMode(mode.Perm()),
		DeviceID: devID,
	}
	return a.writer.WriteHeader(hdr)
}

// Close finalizes the archive
func (a *Archive) Close() error {
	return a.writer.Close()
}
