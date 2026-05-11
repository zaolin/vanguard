package luks

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

var (
	debugKDF = os.Getenv("VANGUARD_LUKS_DEBUG") == "1"
	debugLog = os.Stderr
)

func kdfDebug(format string, args ...interface{}) {
	if debugKDF {
		fmt.Fprintf(debugLog, "[LUKS2-KDF] "+format, args...)
	}
}

// LUKS v2 format is specified here
// https://habd.as/post/external-backup-drive-encryption/assets/luks2_doc_wip.pdf
type headerV2 struct {
	Magic             [6]byte
	Version           uint16
	HeaderSize        uint64
	SequenceID        uint64
	Label             [48]byte
	ChecksumAlgorithm [32]byte
	Salt              [64]byte
	UUID              [40]byte
	SubsystemLabel    [48]byte
	HeaderOffset      uint64
	_                 [184]byte // padding
	Checksum          [64]byte
	// padding of size 7*512
}

type deviceV2 struct {
	path  string
	f     *os.File
	hdr   *headerV2
	meta  *metadata
	flags []string
}

func initV2Device(path string, f *os.File) (*deviceV2, error) {
	var hdr headerV2

	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	if err := binary.Read(f, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	hdrSize := hdr.HeaderSize // size of header + JSON metadata
	if !isPowerOfTwo(uint(hdrSize)) || hdrSize < 16384 || hdrSize > 4194304 {
		return nil, fmt.Errorf("Invalid size of LUKS header: %v", hdrSize)
	}

	// read the whole header
	data := make([]byte, hdrSize)
	if _, err := f.ReadAt(data, 0); err != nil {
		return nil, err
	}

	for i := 0; i < 64; i++ {
		// clear the checksum
		data[int(unsafe.Offsetof(hdr.Checksum))+i] = 0
	}

	// calculate the checksum of the whole header
	var h hash.Hash
	algo := fixedArrayToString(hdr.ChecksumAlgorithm[:])
	switch algo {
	case "sha256":
		h = sha256.New()
	default:
		return nil, fmt.Errorf("Unknown header checksum algorithm: %v", algo)
	}

	h.Write(data)

	checksum := h.Sum(make([]byte, 0))
	expectedChecksum := hdr.Checksum[:h.Size()]
	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, fmt.Errorf("Invalid header checksum")
	}

	var meta metadata
	jsonData := data[4096:]
	jsonData = jsonData[:bytes.IndexByte(jsonData, 0)]

	if err := json.Unmarshal(jsonData, &meta); err != nil {
		return nil, err
	}

	return &deviceV2{
		path:  path,
		f:     f,
		hdr:   &hdr,
		meta:  &meta,
		flags: meta.Config.Flags,
	}, nil
}

func (d *deviceV2) Close() error {
	return d.f.Close()
}

func (d *deviceV2) Path() string {
	return d.path
}

func (d *deviceV2) Slots() []int {
	var normPrio, highPrio []int
	for i, k := range d.meta.Keyslots {
		if k.Priority != nil && *k.Priority == 2 {
			highPrio = append(highPrio, i)
		} else if k.Priority == nil || *k.Priority == 1 {
			normPrio = append(normPrio, i)
		}
	}
	// first we append high priority slots, then normal priority
	return append(highPrio, normPrio...)
}

func (d *deviceV2) Tokens() ([]Token, error) {
	var tokens []Token

	type tokenNode struct {
		Type     string
		Keyslots []json.Number
	}

	for i, t := range d.meta.Tokens {
		var node tokenNode
		if err := json.Unmarshal(t, &node); err != nil {
			return nil, err
		}

		keyslots := make([]int, len(node.Keyslots))
		for j, s := range node.Keyslots {
			slotID, err := s.Int64()
			if err != nil {
				return nil, err
			}
			keyslots[j] = int(slotID)
		}

		token := Token{
			ID:      i,
			Slots:   keyslots,
			Type:    node.Type,
			Payload: t,
		}

		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (d *deviceV2) UUID() string {
	return fixedArrayToString(d.hdr.UUID[:])
}

func (d *deviceV2) FlagsGet() []string {
	return d.flags
}

func (d *deviceV2) FlagsAdd(flags ...string) error {
	d.flags = append(d.flags, flags...)
	return nil
}

func (d *deviceV2) FlagsClear() {
	d.flags = nil
}

func (d *deviceV2) Version() int {
	return 2
}

func (d *deviceV2) Unlock(keyslot int, passphrase []byte, dmName string) error {
	volume, err := d.UnsealVolume(keyslot, passphrase)
	if err != nil {
		return err
	}
	defer clearSlice(volume.key)

	return volume.SetupMapper(dmName)
}

func (d *deviceV2) UnlockAny(passphrase []byte, dmName string) error {
	for _, s := range d.Slots() {
		volume, err := d.UnsealVolume(s, passphrase)
		if err == ErrPassphraseDoesNotMatch {
			continue
		} else if err != nil {
			return err
		}

		return volume.SetupMapper(dmName)
	}
	return ErrPassphraseDoesNotMatch
}

func (d *deviceV2) UnsealVolume(keyslotIdx int, passphrase []byte) (*Volume, error) {
	keyslots := d.meta.Keyslots

	keyslot, ok := keyslots[keyslotIdx]
	if !ok {
		return nil, fmt.Errorf("Unable to get a keyslot with id: %d", keyslotIdx)
	}

	kdfDebug("keyslot=%d kdf=%s hash=%s iterations=%d salt_hex=%s area_key_size=%d area_enc=%s area_offset=%s af_hash=%s\n",
		keyslotIdx, keyslot.Kdf.Type, keyslot.Kdf.Hash, keyslot.Kdf.Iterations,
		keyslot.Kdf.Salt, keyslot.Area.KeySize, keyslot.Area.Encryption,
		keyslot.Area.Offset, keyslot.Af.Hash)

	afKey, err := deriveLuks2AfKey(keyslot.Kdf, keyslotIdx, passphrase, keyslot.Area.KeySize)
	if err != nil {
		return nil, err
	}
	defer clearSlice(afKey)

	kdfDebug("keyslot=%d af_key_len=%d af_key_first=0x%02x af_key_last=0x%02x\n",
		keyslotIdx, len(afKey), afKey[0], afKey[len(afKey)-1])

	finalKey, err := d.decryptLuks2VolumeKey(keyslotIdx, keyslot, afKey)
	if err != nil {
		return nil, err
	}

	kdfDebug("keyslot=%d vol_key_len=%d vol_key_first=0x%02x vol_key_last=0x%02x\n",
		keyslotIdx, len(finalKey), finalKey[0], finalKey[len(finalKey)-1])

	// verify with digest
	digest := d.findDigestForKeyslot(keyslotIdx)
	if digest == nil {
		return nil, fmt.Errorf("No digest is found for keyslot %v", keyslotIdx)
	}

	generatedDigest, err := computeDigestForKey(digest, keyslotIdx, finalKey)
	if err != nil {
		return nil, err
	}
	defer clearSlice(generatedDigest)

	expectedDigest, err := base64.StdEncoding.DecodeString(digest.Digest)
	if err != nil {
		return nil, fmt.Errorf("keyslotIdx[%v].digest.Digest base64 parsing failed: %v", keyslotIdx, err)
	}
	if !bytes.Equal(generatedDigest[0:len(expectedDigest)], expectedDigest) {
		return nil, ErrPassphraseDoesNotMatch
	}
	clearSlice(generatedDigest)

	if len(digest.Segments) != 1 {
		return nil, fmt.Errorf("LUKS partition expects exactly 1 storage segment, got %+v", len(digest.Segments))
	}
	seg, err := digest.Segments[0].Int64()
	if err != nil {
		return nil, err
	}

	storageSegment := d.meta.Segments[int(seg)]
	offset, err := storageSegment.Offset.Int64()
	if err != nil {
		return nil, err
	}

	var storageSize uint64
	if storageSegment.Size == "dynamic" {
		storageSize, err = fileSize(d.f)
		if err != nil {
			return nil, err
		}
		if storageSize < uint64(offset) {
			return nil, fmt.Errorf("backing file size %d is smaller than LUKS segment offset %d", storageSize, offset)
		}

		storageSize -= uint64(offset)
	} else {
		size, err := strconv.Atoi(storageSegment.Size)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, fmt.Errorf("invalid segment size: %v", size)
		}

		storageSize = uint64(size)
	}

	ivTweak, err := storageSegment.IvTweak.Int64()
	if err != nil {
		return nil, err
	}

	v := &Volume{
		BackingDevice:     d.path,
		Flags:             d.flags,
		UUID:              d.UUID(),
		key:               finalKey,
		LuksType:          "LUKS2",
		StorageSize:       storageSize,
		StorageOffset:     uint64(offset),
		StorageEncryption: storageSegment.Encryption,
		StorageIvTweak:    uint64(ivTweak),
		StorageSectorSize: uint64(storageSegment.SectorSize),
	}
	return v, nil
}

func computeDigestForKey(dig *digest, keyslotIdx int, finalKey []byte) ([]byte, error) {
	digSalt, err := base64.StdEncoding.DecodeString(dig.Salt)
	if err != nil {
		return nil, fmt.Errorf("keyslotIdx[%v].digest.salt base64 parsing failed: %v", keyslotIdx, err)
	}

	switch dig.Type {
	case "pbkdf2":
		h, size := getHashAlgo(dig.Hash)
		if h == nil {
			return nil, fmt.Errorf("Unknown digest hash algorithm: %v", dig.Hash)
		}
		return pbkdf2.Key(finalKey, digSalt, int(dig.Iterations), size, h), nil
	default:
		return nil, fmt.Errorf("Unknown digest kdf type: %v", dig.Type)
	}
}

func (d *deviceV2) decryptLuks2VolumeKey(keyslotIdx int, keyslot keyslot, afKey []byte) ([]byte, error) {
	area := keyslot.Area

	keyslotSize := keyslot.KeySize * stripesNum

	areaSize, err := area.Size.Int64()
	if err != nil {
		return nil, fmt.Errorf("Invalid keyslotIdx[%v] size value: %v. %v", keyslotIdx, area.Size, err)
	}
	if int64(keyslotSize) > areaSize {
		return nil, fmt.Errorf("keyslot[%v] area size too small, given %v expected at least %v", keyslotIdx, areaSize, keyslotSize)
	}
	if keyslotSize%storageSectorSize != 0 {
		return nil, fmt.Errorf("keyslot[%v] size %v is not multiple of the sector size %v", keyslotIdx, keyslotSize, storageSectorSize)
	}

	keyData := make([]byte, keyslotSize)
	defer clearSlice(keyData)

	keyslotOffset, err := area.Offset.Int64()
	if err != nil {
		return nil, fmt.Errorf("Invalid keyslotIdx[%v] offset: %v. %v", keyslotIdx, area.Offset, err)
	}
	if keyslotOffset%storageSectorSize != 0 {
		return nil, fmt.Errorf("keyslot[%v] offset %v is not aligned to sector size %v", keyslotIdx, keyslotOffset, storageSectorSize)
	}

	if _, err := d.f.ReadAt(keyData, keyslotOffset); err != nil {
		return nil, err
	}

	dec, err := newLuks2SectorDecrypter(area.Encryption, afKey)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(keyslotSize/storageSectorSize); i++ {
		block := keyData[i*storageSectorSize : (i+1)*storageSectorSize]
		dec.DecryptSector(block, uint64(i))
	}

	af := keyslot.Af
	if af.Stripes != stripesNum {
		return nil, fmt.Errorf("LUKS currently supports only af with 4000 stripes")
	}
	h, _ := getHashAlgo(af.Hash)
	if h == nil {
		return nil, fmt.Errorf("Unknown af hash algorithm: %v", af.Hash)
	}

	return afMerge(keyData, int(keyslot.KeySize), int(af.Stripes), h())
}

type luks2SectorDecrypter struct {
	dataBlock  cipher.Block
	tweakBlock cipher.Block
	essivBlock cipher.Block
}

func newLuks2SectorDecrypter(encryption string, afKey []byte) (*luks2SectorDecrypter, error) {
	encParts := strings.Split(encryption, "-")
	if len(encParts) < 3 {
		return nil, fmt.Errorf("Unexpected encryption format: %v", encryption)
	}
	cipherName := encParts[0]
	cipherMode := encParts[1]

	if cipherMode != "xts" {
		return nil, fmt.Errorf("Unknown encryption mode: %v", cipherMode)
	}

	cipherFunc, err := getCipher(cipherName)
	if err != nil {
		return nil, err
	}

	dataKey := afKey[:len(afKey)/2]
	dataBlock, err := cipherFunc(dataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create data cipher: %w", err)
	}

	tweakKey := afKey[len(afKey)/2:]
	tweakBlock, err := cipherFunc(tweakKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tweak cipher: %w", err)
	}

	d := &luks2SectorDecrypter{
		dataBlock:  dataBlock,
		tweakBlock: tweakBlock,
	}

	// ESSIV: "aes-xts-essiv:sha256" → Split("-") → ["aes","xts","essiv:sha256"]
	// ESSIV computes the IV, XTS tweak key still encrypts it to produce the tweak.
	if len(encParts) >= 3 && strings.HasPrefix(encParts[2], "essiv:") {
		hashAlg := encParts[2][6:]
		hashFn, _ := getHashAlgo(hashAlg)
		if hashFn == nil {
			return nil, fmt.Errorf("unknown ESSIV hash algorithm: %v", hashAlg)
		}
		h := hashFn()
		h.Write(afKey)
		essivKey := h.Sum(nil)
		kdfDebug("ESSIV mode: hash=%s → essivKey_len=%d\n", hashAlg, len(essivKey))
		d.essivBlock, err = cipherFunc(essivKey)
		if err != nil {
			return nil, fmt.Errorf("ESSIV cipher init failed: %w", err)
		}
	}

	return d, nil
}

func (d *luks2SectorDecrypter) DecryptSector(sectorData []byte, sectorNum uint64) {
	// Step 1: Compute the IV
	// Plain64: IV = le64(sectorNum)
	// ESSIV:   IV = AES-ECB(essiv_key, le64(sectorNum))
	var iv [16]byte
	binary.LittleEndian.PutUint64(iv[:8], sectorNum)
	if d.essivBlock != nil {
		d.essivBlock.Encrypt(iv[:], iv[:])
	}

	// Step 2: Compute tweak = AES-ECB(tweak_key, IV)
	var tweak [16]byte
	copy(tweak[:], iv[:])
	d.tweakBlock.Encrypt(tweak[:], tweak[:])

	// Step 3: XTS decrypt with data key and tweak
	xtsDecryptSector(d.dataBlock, sectorData, sectorData, tweak)
}

func deriveLuks2AfKey(kdf kdf, keyslotIdx int, passphrase []byte, keyLength uint) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(kdf.Salt)
	if err != nil {
		return nil, fmt.Errorf("keyslotIdx[%v].kdf.salt base64 parsing failed: %v", keyslotIdx, err)
	}

	var afKey []byte

	switch kdf.Type {
	case "pbkdf2":
		var h func() hash.Hash
		switch kdf.Hash {
		case "sha256":
			h = sha256.New
		case "sha512":
			h = sha512.New
		default:
			return nil, fmt.Errorf("Unknown keyslotIdx[%v].kdf.hash algorithm: %v", keyslotIdx, kdf.Hash)
		}
		afKey = pbkdf2.Key(passphrase, salt, int(kdf.Iterations), int(keyLength), h)
	case "argon2i":
		afKey = argon2.Key(passphrase, salt, uint32(kdf.Time), uint32(kdf.Memory), uint8(kdf.Cpus), uint32(keyLength))
	case "argon2id":
		afKey = argon2.IDKey(passphrase, salt, uint32(kdf.Time), uint32(kdf.Memory), uint8(kdf.Cpus), uint32(keyLength))
	default:
		return nil, fmt.Errorf("Unknown kdf type: %v", kdf.Type)
	}

	return afKey, nil
}

func (d *deviceV2) findDigestForKeyslot(keyslotIdx int) *digest {
	for _, dig := range d.meta.Digests {
		for _, k := range dig.Keyslots {
			k, e := k.Int64()
			if e != nil {
				continue
			}
			if int(k) == keyslotIdx {
				return &dig
			}
		}
	}
	return nil
}
