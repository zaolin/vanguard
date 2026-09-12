package luks

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"os"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// LUKS v1 format is specified here
// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
type headerV1 struct {
	Magic         [6]byte
	Version       uint16
	CipherName    [32]byte
	CipherMode    [32]byte
	HashSpec      [32]byte
	PayloadOffset uint32
	KeyBytes      uint32
	MkDigest      [20]byte
	MkDigestSalt  [32]byte
	MkDigestIter  uint32
	UUID          [40]byte
	KeySlots      [8]keySlot
}

type keySlot struct {
	Active            uint32
	Iterations        uint32
	Salt              [32]byte
	KeyMaterialOffset uint32 // offset in sectors
	Stripes           uint32
}

const luksV1SlotEnabled = 0xAC71F3

type deviceV1 struct {
	path  string
	f     *os.File
	hdr   *headerV1
	flags []string
}

func initV1Device(path string, f *os.File) (*deviceV1, error) {
	var hdr headerV1

	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	if err := binary.Read(f, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	return &deviceV1{path: path, f: f, hdr: &hdr}, nil
}

func (d *deviceV1) Close() error {
	return d.f.Close()
}

func (d *deviceV1) Path() string {
	return d.path
}

func (d *deviceV1) Slots() []int {
	slots := make([]int, 0)

	for id, ks := range d.hdr.KeySlots {
		if ks.Active != luksV1SlotEnabled {
			continue
		}

		slots = append(slots, id)
	}

	return slots
}

func (d *deviceV1) UUID() string {
	return fixedArrayToString(d.hdr.UUID[:])
}

func (d *deviceV1) FlagsGet() []string {
	return d.flags
}

func (d *deviceV1) FlagsAdd(flags ...string) error {
	d.flags = append(d.flags, flags...)
	return nil
}

func (d *deviceV1) FlagsClear() {
	d.flags = nil
}

func (d *deviceV1) Version() int {
	return 1
}

func (d *deviceV1) Unlock(keyslot int, passphrase []byte, dmName string) error {
	volume, err := d.UnsealVolume(keyslot, passphrase)
	if err != nil {
		return err
	}
	defer clearSlice(volume.key)

	return volume.SetupMapper(dmName)
}

func (d *deviceV1) UnlockAny(passphrase []byte, dmName string) error {
	for k, s := range d.hdr.KeySlots {
		if s.Active != luksV1SlotEnabled {
			continue
		}

		volume, err := d.UnsealVolume(k, passphrase)
		if err == ErrPassphraseDoesNotMatch {
			continue
		} else if err != nil {
			return err
		}

		// Wipe the master key after setting up the dm-crypt mapper.
		// The kernel has its own copy; we don't need ours anymore.
		defer clearSlice(volume.key)
		return volume.SetupMapper(dmName)
	}
	return ErrPassphraseDoesNotMatch
}

func (d *deviceV1) UnsealVolume(keyslotIdx int, passphrase []byte) (*Volume, error) {
	keyslots := d.hdr.KeySlots
	if keyslotIdx < 0 || keyslotIdx >= len(keyslots) {
		return nil, fmt.Errorf("keyslot %d is out of range of available slots", keyslotIdx)
	}
	slot := keyslots[keyslotIdx]

	algo := fixedArrayToString(d.hdr.HashSpec[:])
	h, _ := getHashAlgo(algo)
	if h == nil {
		return nil, fmt.Errorf("Unknown hash spec algorithm: %v", algo)
	}

	afKey, err := deriveLuks1AfKey(passphrase, slot, int(d.hdr.KeyBytes), h)
	if err != nil {
		return nil, fmt.Errorf("keyslot %d: %w", keyslotIdx, err)
	}
	defer clearSlice(afKey)

	finalKey, err := d.decryptLuks1VolumeKey(keyslotIdx, slot, afKey, h)
	if err != nil {
		return nil, err
	}

	// verify with digest
	generatedDigest := pbkdf2.Key(finalKey, d.hdr.MkDigestSalt[:], int(d.hdr.MkDigestIter), int(d.hdr.KeyBytes), h)
	defer clearSlice(generatedDigest)
	if !bytes.Equal(generatedDigest[:20], d.hdr.MkDigest[:]) {
		return nil, ErrPassphraseDoesNotMatch
	}

	encryption := fixedArrayToString(d.hdr.CipherName[:]) + "-" + fixedArrayToString(d.hdr.CipherMode[:])

	storageOffset := uint64(d.hdr.PayloadOffset) * storageSectorSize

	storageSize, err := fileSize(d.f)
	if err != nil {
		return nil, err
	}
	if storageSize < storageOffset {
		return nil, fmt.Errorf("backing file size %d is smaller than LUKS segment offset %d", storageSize, storageOffset)
	}
	storageSize -= storageOffset

	v := Volume{
		BackingDevice:     d.path,
		Flags:             d.flags,
		UUID:              d.UUID(),
		key:               finalKey,
		LuksType:          "LUKS1",
		StorageSize:       storageSize,
		StorageOffset:     storageOffset,
		StorageEncryption: encryption,
		StorageIvTweak:    0,
		StorageSectorSize: storageSectorSize,
	}

	return &v, nil
}

func (d *deviceV1) decryptLuks1VolumeKey(keyslotIdx int, slot keySlot, afKey []byte, h func() hash.Hash) ([]byte, error) {
	// decrypt keyslotIdx area using the derived key
	// Validate keyslot size to prevent integer overflow / OOM from a crafted header
	const maxKeyslotSize = 64 * 1024 * 1024 // 64MB max keyslot area
	keyslotSize := uint64(d.hdr.KeyBytes) * uint64(stripesNum)
	if keyslotSize > maxKeyslotSize {
		return nil, fmt.Errorf("keyslot[%v] size %d exceeds maximum %d — possible crafted header", keyslotIdx, keyslotSize, maxKeyslotSize)
	}
	if keyslotSize%uint64(storageSectorSize) != 0 {
		return nil, fmt.Errorf("keyslot[%v] size %v is not multiple of the sector size %v", keyslotIdx, keyslotSize, storageSectorSize)
	}
	keyData := make([]byte, keyslotSize)
	defer clearSlice(keyData)

	if _, err := d.f.ReadAt(keyData, int64(slot.KeyMaterialOffset)*storageSectorSize); err != nil {
		return nil, err
	}

	ciph, err := d.buildLuks1AfCipher(afKey)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(keyslotSize/storageSectorSize); i++ {
		block := keyData[i*storageSectorSize : (i+1)*storageSectorSize]
		ciph.Decrypt(block, block, uint64(i))
	}

	// anti-forensic merge
	if slot.Stripes != stripesNum {
		return nil, fmt.Errorf("LUKS currently supports only af with 4000 stripes")
	}
	return afMerge(keyData, int(d.hdr.KeyBytes), int(slot.Stripes), h())
}

func (d *deviceV1) buildLuks1AfCipher(afKey []byte) (*xts.Cipher, error) {
	var cipherFunc func(key []byte) (cipher.Block, error)

	cipherName := fixedArrayToString(d.hdr.CipherName[:])
	cipherFunc, err := getCipher(cipherName)
	if err != nil {
		return nil, err
	}

	cipherMode := fixedArrayToString(d.hdr.CipherMode[:])
	switch cipherMode {
	case "xts-plain64":
		return xts.NewCipher(cipherFunc, afKey)
	default:
		return nil, fmt.Errorf("Unknown encryption mode: %v", cipherMode)
	}
}

var (
	luksMetaMagic    = []byte("LUKSMETA")
	luksMetaNullUUID = make([]byte, 16)
)

type luksMetaSlot struct {
	UUID   [16]byte
	Offset uint32
	Length uint32
	Crc32  uint32
	_      uint32
}

type luksMetaHeader struct {
	Magic   [8]byte
	Version uint32
	Crc32   uint32
	Slots   [8]luksMetaSlot
}

// readLuksMeta read non-standard metadata information for LUKS v1
// It follows implementation defined at https://github.com/latchset/luksmeta
func (d *deviceV1) Tokens() ([]Token, error) {
	var hdr luksMetaHeader
	data := make([]byte, unsafe.Sizeof(hdr))

	// Compute the luksmeta "hole" offset after the keyslot material. All
	// arithmetic in 64-bit: KeyMaterialOffset is a raw uint32 from disk and
	// *512 overflows uint32 for crafted values.
	var holeOffset int64
	length := int64(d.hdr.KeyBytes) * int64(stripesNum)
	for _, s := range d.hdr.KeySlots {
		offset := int64(s.KeyMaterialOffset) * int64(storageSectorSize)
		if holeOffset < offset+length {
			holeOffset = offset + length
		}
	}
	if holeOffset < 0 || holeOffset > maxLuks1HoleOffset {
		return nil, fmt.Errorf("LUKS1 luksmeta hole offset out of range (%d) — header may be corrupt", holeOffset)
	}
	holeOffset = int64(roundUp(int(holeOffset), 4096))

	if _, err := d.f.ReadAt(data, holeOffset); err != nil {
		return nil, err
	}
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	tokens := make([]Token, 0)
	if !bytes.Equal(hdr.Magic[:], luksMetaMagic) {
		return tokens, nil
	}

	crcFieldOffset := unsafe.Offsetof(hdr.Crc32)
	clearSlice(data[crcFieldOffset : crcFieldOffset+4])
	hdrChecksum := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err := hdrChecksum.Write(data); err != nil {
		return nil, err
	}
	if hdrChecksum.Sum32() != hdr.Crc32 {
		return nil, fmt.Errorf("Luks Meta header CRC error")
	}

	for i, s := range hdr.Slots {
		if !bytes.Equal(s.UUID[:], luksMetaNullUUID) {
			// Bound the token payload: s.Length is a raw uint32 from the
			// (unauthenticated) luksmeta header — an unbounded make would
			// allow a 4GiB OOM from a corrupt header.
			const maxTokenPayload = 1 << 20 // 1 MiB
			if s.Length == 0 || s.Length > maxTokenPayload {
				return nil, fmt.Errorf("Luks Meta token #%d: invalid payload length %d", i, s.Length)
			}
			payload := make([]byte, s.Length)
			if _, err := d.f.ReadAt(payload, holeOffset+int64(s.Offset)); err != nil {
				return nil, err
			}
			tokenChecksum := crc32.New(crc32.MakeTable(crc32.Castagnoli))
			if _, err := tokenChecksum.Write(payload); err != nil {
				return nil, err
			}
			if tokenChecksum.Sum32() != s.Crc32 {
				return nil, fmt.Errorf("Luks Meta token #%d CRC error", i)
			}

			t := Token{
				ID:      i,
				Slots:   []int{i},
				Type:    luksMetaTokenType(s.UUID[:]),
				Payload: payload,
			}
			tokens = append(tokens, t)
		}
	}

	return tokens, nil
}

var clevisUUID = []byte{0xcb, 0x6e, 0x89, 0x04, 0x81, 0xff, 0x40, 0xda, 0xa8, 0x4a, 0x07, 0xab, 0x9a, 0xb5, 0x71, 0x5e}

func luksMetaTokenType(uuid []byte) string {
	if bytes.Equal(uuid, clevisUUID) {
		return "clevis"
	}

	return ""
}

func deriveLuks1AfKey(passphrase []byte, slot keySlot, keySize int, h func() hash.Hash) ([]byte, error) {
	// Refuse absurd iteration counts instead of capping: capping changes the
	// KDF output, which guarantees the master-key digest check fails — the
	// user would type a correct passphrase and see "wrong passphrase" on
	// every attempt (fail-closed boot failure that looks like data loss).
	// 10M PBKDF2-SHA1 iterations is ~2x cryptsetup's historical maximum;
	// real headers stay orders of magnitude below.
	const maxIterations = 10_000_000
	iterations := int(slot.Iterations)
	if iterations <= 0 || iterations > maxIterations {
		return nil, fmt.Errorf("LUKS1 keyslot iteration count out of range (%d, max %d) — header may be corrupt", slot.Iterations, maxIterations)
	}
	return pbkdf2.Key(passphrase, slot.Salt[:], iterations, keySize, h), nil
}
