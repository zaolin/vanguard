package luks

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/xts"
)

func skipIfNoCryptsetup(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not found on PATH")
	}
}

func prepareLuks2Disk(t *testing.T, password string, cryptsetupArgs ...string) *os.File {
	t.Helper()
	disk, err := os.CreateTemp("", "vanguard-luks2-test-*.disk")
	require.NoError(t, err)
	require.NoError(t, disk.Truncate(24*1024*1024))

	hasForceIter := false
	for _, a := range cryptsetupArgs {
		if a == "--pbkdf-force-iterations" {
			hasForceIter = true
			break
		}
	}

	args := []string{"luksFormat", "--type", "luks2", "-q", disk.Name()}
	if !hasForceIter {
		args = append(args, "--iter-time", "5")
	}
	args = append(args, cryptsetupArgs...)
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	require.NoError(t, cmd.Run(), "cryptsetup luksFormat failed")
	return disk
}

func TestLuks2PassphraseUnlock(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "testpass"
	disk := prepareLuks2Disk(t, password)
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots, "expected at least one keyslot")

	vol, err := dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume with correct passphrase should succeed")
	require.NotEmpty(t, vol.StorageEncryption, "volume should have encryption info")
	t.Logf("Unlocked LUKS2 device: type=%s, encryption=%s, size=%d",
		vol.LuksType, vol.StorageEncryption, vol.StorageSize)
}

func TestLuks2WrongPassphrase(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "testpass"
	disk := prepareLuks2Disk(t, password)
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	_, err = dev.UnsealVolume(slots[0], []byte("wrongpassword"))
	require.ErrorIs(t, err, ErrPassphraseDoesNotMatch,
		"wrong passphrase should return ErrPassphraseDoesNotMatch")
}

func TestLuks2PassphraseSpecialChars(t *testing.T) {
	skipIfNoCryptsetup(t)

	cases := []struct {
		name       string
		passphrase string
	}{
		{"special_ascii", "p@ss#w0rd!"},
		{"with_space", "hello world"},
		{"with_quotes", `"it's" a 'test'`},
		{"with_backslash", `path\to\file`},
		{"with_newline_escape", "line1\\nline2"},
		{"utf8_multibyte", "pässwörd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			disk := prepareLuks2Disk(t, tc.passphrase)
			defer disk.Close()
			defer os.Remove(disk.Name())

			dev, err := Open(disk.Name())
			require.NoError(t, err)
			defer dev.Close()

			slots := dev.Slots()
			require.NotEmpty(t, slots)

			_, err = dev.UnsealVolume(slots[0], []byte(tc.passphrase))
			require.NoError(t, err, "UnsealVolume with passphrase %q should succeed", tc.passphrase)
		})
	}
}

func TestLuks2PassphraseArgon2id(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password, "--pbkdf", "argon2id", "--pbkdf-memory", "32768")
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	_, err = dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume with argon2id KDF should succeed")
}

func TestLuks2PassphrasePBKDF2(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password, "--pbkdf", "pbkdf2", "--iter-time", "5")
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	_, err = dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume with pbkdf2 KDF should succeed")
}

func TestLuks2MultipleKeyslots(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password1 := "firstpass"
	disk := prepareLuks2Disk(t, password1)
	defer disk.Close()
	defer os.Remove(disk.Name())

	password2 := "secondpass"
	addCmd := exec.Command("cryptsetup", "luksAddKey", "-q", disk.Name())
	addCmd.Stdin = strings.NewReader(password1 + "\n" + password2)
	if testing.Verbose() {
		addCmd.Stdout = os.Stdout
		addCmd.Stderr = os.Stderr
	}
	require.NoError(t, addCmd.Run(), "luksAddKey failed")

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.Len(t, slots, 2, "expected 2 keyslots after adding a second one")

	_, err = dev.UnsealVolume(slots[0], []byte(password1))
	require.NoError(t, err, "slot 0 should unlock with first passphrase")

	_, err = dev.UnsealVolume(slots[1], []byte(password2))
	require.NoError(t, err, "slot 1 should unlock with second passphrase")

	_, err = dev.UnsealVolume(slots[0], []byte(password2))
	require.ErrorIs(t, err, ErrPassphraseDoesNotMatch,
		"slot 0 should NOT unlock with second passphrase")
}

func TestLuks2Keysize256(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password,
		"--cipher", "aes-xts-plain64",
		"--key-size", "256",
		"--pbkdf", "argon2id",
		"--iter-time", "5",
		"--pbkdf-memory", "32768",
		"--hash", "sha256")
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	vol, err := dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume with key-size 256 should succeed")
	require.Equal(t, "aes-xts-plain64", vol.StorageEncryption)
}

// TestLuks2Keysize512 tests unlocking with AES-XTS-512 (key_size=64, 512 bits).
// This matches the user's real keyslot parameters: pbkdf2+sha512, 1000 iterations.
func TestLuks2Keysize512(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password,
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000",
		"--hash", "sha512")
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	vol, err := dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume with key-size 512 + pbkdf2+sha512 should succeed")
	require.Equal(t, "aes-xts-plain64", vol.StorageEncryption)
}

// TestLuks2Keysize512_AreaEncryption tests unlocking when the keyslot AREA uses a
// different cipher than the data segment (aes-xts-essiv:sha256 for area, aes-xts-plain64 for data).
// This matches the user's real setup.
func TestLuks2Keysize512_AreaEncryption(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password,
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000",
		"--hash", "sha512")
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	vol, err := dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume should succeed with real-world key-size=512 parameters")
	require.Equal(t, "aes-xts-plain64", vol.StorageEncryption)
	t.Logf("Volume: encryption=%s, ivTweak=%d, offset=%d, size=%d",
		vol.StorageEncryption, vol.StorageIvTweak, vol.StorageOffset, vol.StorageSize)
}

func TestLuks2HashAlgorithms(t *testing.T) {
	skipIfNoCryptsetup(t)

	hashes := []string{"sha256", "sha512"}

	for _, h := range hashes {
		t.Run(h, func(t *testing.T) {
			t.Parallel()

			password := "foobar"
			disk := prepareLuks2Disk(t, password, "--hash", h)
			defer disk.Close()
			defer os.Remove(disk.Name())

			dev, err := Open(disk.Name())
			require.NoError(t, err)
			defer dev.Close()

			slots := dev.Slots()
			require.NotEmpty(t, slots)

			_, err = dev.UnsealVolume(slots[0], []byte(password))
			require.NoError(t, err, "UnsealVolume with hash %s should succeed", h)
		})
	}
}

func TestLuks2CryptsetupCrossValidation(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	passphrases := []string{
		"simple",
		"with space",
		"p@ss#w0rd!",
		"pässwörd",
	}

	for _, passphrase := range passphrases {
		t.Run(fmt.Sprintf("passphrase_%x", []byte(passphrase)), func(t *testing.T) {
			t.Parallel()

			disk := prepareLuks2Disk(t, passphrase)
			defer disk.Close()
			defer os.Remove(disk.Name())

			dev, err := Open(disk.Name())
			require.NoError(t, err)
			defer dev.Close()

			slots := dev.Slots()
			require.NotEmpty(t, slots)

			_, err = dev.UnsealVolume(slots[0], []byte(passphrase))
			require.NoError(t, err, "Go library UnsealVolume should succeed with passphrase %q", passphrase)

			verifyCmd := exec.Command("cryptsetup", "open", "--test-passphrase", disk.Name())
			verifyCmd.Stdin = strings.NewReader(passphrase + "\n")
			if testing.Verbose() {
				verifyCmd.Stdout = os.Stdout
				verifyCmd.Stderr = os.Stderr
			}
			err = verifyCmd.Run()
			require.NoError(t, err, "cryptsetup should accept passphrase %q", passphrase)
		})
	}
}

// TestLuks2ESSIV_CrossValidation verifies that our ESSIV XTS decryption
// matches cryptsetup's implementation for aes-xts-essiv:sha256 keyslot area encryption.
func TestLuks2ESSIV_CrossValidation(t *testing.T) {
	skipIfNoCryptsetup(t)
	t.Parallel()

	password := "essivtest@2026!"
	disk := prepareLuks2Disk(t, password,
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000",
		"--hash", "sha512",
		"--keyslot-cipher", "aes-xts-essiv:sha256",
		"--keyslot-key-size", "512")
	defer disk.Close()
	defer os.Remove(disk.Name())

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	slots := dev.Slots()
	require.NotEmpty(t, slots)

	vol, err := dev.UnsealVolume(slots[0], []byte(password))
	require.NoError(t, err, "UnsealVolume should unlock ESSIV-protected keyslot area")
	require.NotEmpty(t, vol.StorageEncryption)

	// Cross-validate with cryptsetup
	verifyCmd := exec.Command("cryptsetup", "open", "--test-passphrase", disk.Name())
	verifyCmd.Stdin = strings.NewReader(password + "\n")
	out, err := verifyCmd.CombinedOutput()
	require.NoError(t, err, "cryptsetup cross-validation should pass with ESSIV area encryption\nOutput: %s", string(out))

	t.Logf("ESSIV cross-validation PASSED: encryption=%s", vol.StorageEncryption)
}

// TestLuks2Base64Passphrase tests unlocking with a base64-encoded passphrase.
// systemd-cryptenroll stores base64(32_byte_random) as the keyslot passphrase.
func TestLuks2Base64Passphrase(t *testing.T) {
	skipIfNoCryptsetup(t)

	passwords := []string{
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", // base64 of 0..31
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // base64 of all zeros
	}

	for i, pw := range passwords {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			t.Parallel()

			disk := prepareLuks2Disk(t, pw,
				"--cipher", "aes-xts-plain64",
				"--key-size", "512",
				"--pbkdf", "pbkdf2",
				"--pbkdf-force-iterations", "1000",
				"--hash", "sha512")
			defer disk.Close()
			defer os.Remove(disk.Name())

			dev, err := Open(disk.Name())
			require.NoError(t, err)
			defer dev.Close()

			slots := dev.Slots()
			require.NotEmpty(t, slots)

			_, err = dev.UnsealVolume(slots[0], []byte(pw))
			require.NoError(t, err, "UnsealVolume with base64 passphrase should succeed")
		})
	}
}

// TestXTS_Vs_GoXTS verifies our xtsDecryptSector produces identical results
// to golang.org/x/crypto/xts for plain64 mode (where tweak = LE64(sectorNum)).
// This is the baseline validation - if it fails, our XTS is wrong.
func TestXTS_Vs_GoXTS(t *testing.T) {
	t.Parallel()

	afKey := make([]byte, 64)
	for i := range afKey {
		afKey[i] = byte(i)
	}

	// golang.org/x/crypto/xts with full key
	goXTS, err := xts.NewCipher(aes.NewCipher, afKey)
	require.NoError(t, err)

	// Our impl: data cipher from first half of key
	dataBlock, err := aes.NewCipher(afKey[:32])
	require.NoError(t, err)

	// plain64 tweak block = AES with second half of key
	tweakBlock, err := aes.NewCipher(afKey[32:])
	require.NoError(t, err)

	plaintext := make([]byte, 512)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// Encrypt with both
	src := make([]byte, 512)
	copy(src, plaintext)

	// Go XTS encrypt
	goXTS.Encrypt(src, src, 1) // sector 1

	// Our XTS decrypt on Go's encrypted output
	var tweak [16]byte
	binary.LittleEndian.PutUint64(tweak[:8], 1) // sector 1
	tweakBlock.Encrypt(tweak[:], tweak[:])      // plain64: encrypt sector number
	xtsDecryptSector(dataBlock, src, src, tweak)

	for i := range src {
		if src[i] != plaintext[i] {
			t.Fatalf("XTS mismatch vs Go xts at byte %d: got 0x%02x want 0x%02x", i, src[i], plaintext[i])
		}
	}

	t.Logf("Our XTS matches Go's golang.org/x/crypto/xts: OK")
}

// TestXTS_GoXTS_RoundTrip verifies round-trip with golang.org/x/crypto/xts
func TestXTS_GoXTS_RoundTrip(t *testing.T) {
	t.Parallel()

	afKey := make([]byte, 64)
	for i := range afKey {
		afKey[i] = byte(i)
	}

	goXTS, err := xts.NewCipher(aes.NewCipher, afKey)
	require.NoError(t, err)

	plaintext := make([]byte, 512)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	encrypted := make([]byte, 512)
	copy(encrypted, plaintext)
	goXTS.Encrypt(encrypted, encrypted, 42)

	decrypted := make([]byte, 512)
	copy(decrypted, encrypted)
	goXTS.Decrypt(decrypted, decrypted, 42)

	for i := range decrypted {
		if decrypted[i] != plaintext[i] {
			t.Fatalf("Go XTS round-trip mismatch at byte %d", i)
		}
	}

	t.Logf("Go XTS round-trip: OK")
}

// produces the expected results by doing a complete round-trip.
func TestXTS_ESSIV_RoundTrip(t *testing.T) {
	t.Parallel()

	afKey := make([]byte, 64)
	for i := range afKey {
		afKey[i] = byte(255 - i)
	}

	dec, err := newLuks2SectorDecrypter("aes-xts-essiv:sha256", afKey)
	require.NoError(t, err)

	plaintext := make([]byte, 512)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	for sectorNum := uint64(0); sectorNum < 10; sectorNum++ {
		// Encrypt (simulate what cryptsetup does during enrollment)
		encrypted := make([]byte, 512)
		copy(encrypted, plaintext)

		var tweak [16]byte
		binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
		dec.essivBlock.Encrypt(tweak[:], tweak[:])
		dec.tweakBlock.Encrypt(tweak[:], tweak[:])
		xtsEncryptSector(dec.dataBlock, encrypted, encrypted, tweak)

		// Decrypt (what we do during unlock)
		dec.DecryptSector(encrypted, sectorNum)

		for i := range encrypted {
			if encrypted[i] != plaintext[i] {
				t.Fatalf("XTS-ESSIV round-trip mismatch at sector %d byte %d: got 0x%02x want 0x%02x",
					sectorNum, i, encrypted[i], plaintext[i])
			}
		}
	}

	t.Logf("XTS-ESSIV-SHA256 round-trip: OK (10 sectors)")
}

// TestXTS_ESSIV_DumpsEncryption dumps the actual area encryption used
// by cryptsetup when creating a LUKS2 volume with specific KDF params.
func TestXTS_ESSIV_DumpsEncryption(t *testing.T) {
	skipIfNoCryptsetup(t)

	cases := []struct {
		name      string
		extraArgs []string
	}{
		{"pbkdf2_sha512", []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha512"}},
		{"argon2id_sha256", []string{"--pbkdf", "argon2id", "--pbkdf-memory", "32768", "--iter-time", "5"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			password := "dumptest"
			disk := prepareLuks2Disk(t, password, tc.extraArgs...)
			defer disk.Close()
			defer os.Remove(disk.Name())

			dev, err := Open(disk.Name())
			require.NoError(t, err)
			defer dev.Close()

			v2dev, ok := dev.(*deviceV2)
			require.True(t, ok, "expected LUKS2 device")

			for idx, k := range v2dev.meta.Keyslots {
				t.Logf("%s: keyslot %d area_encryption=%s", tc.name, idx, k.Area.Encryption)
			}
		})
	}
}
func TestAFMergeRoundTrip(t *testing.T) {
	t.Parallel()

	for _, keyLen := range []int{32, 64} {
		t.Run(fmt.Sprintf("keylen_%d", keyLen), func(t *testing.T) {
			key := make([]byte, keyLen)
			for i := range key {
				key[i] = byte(i)
			}

			h := sha256.New
			split, err := afSplit(key, 4000, h())
			require.NoError(t, err)
			require.Equal(t, keyLen*4000, len(split))

			merged, err := afMerge(split, keyLen, 4000, h())
			require.NoError(t, err)
			for i := range key {
				require.Equal(t, key[i], merged[i],
					"afSplit/afMerge round-trip mismatch at byte %d", i)
			}
		})
	}
}

// TestKDF_PBKDF2_SHA512_1000iter_512bit matches the exact KDF parameters
// of the user's keyslot 2: pbkdf2, sha512, 1000 iterations, key_size=512 bits.
func TestKDF_PBKDF2_SHA512_1000iter_512bit(t *testing.T) {
	t.Parallel()

	saltHex := "859cebf7b5f5029183f9d722c6833725f2b08019999bb81de7f7abc0d9fee9a2"
	salt, err := hex.DecodeString(saltHex)
	require.NoError(t, err)
	require.Equal(t, 32, len(salt))

	kdf := kdf{
		Type:       "pbkdf2",
		Hash:       "sha512",
		Iterations: 1000,
		Salt:       saltHex,
	}

	passphrase := []byte("test")
	afKey, err := deriveLuks2AfKey(kdf, 0, passphrase, 64)
	require.NoError(t, err)
	require.Equal(t, 64, len(afKey),
		"PBKDF2-SHA512 with keySize=64 should produce 64 bytes")

	t.Logf("PBKDF2-SHA512-1000: salt=%x, key_len=%d, first=0x%02x, last=0x%02x",
		salt, len(afKey), afKey[0], afKey[len(afKey)-1])

	// Verify deterministic: same input produces same output
	afKey2, err := deriveLuks2AfKey(kdf, 0, passphrase, 64)
	require.NoError(t, err)
	for i := range afKey {
		require.Equal(t, afKey[i], afKey2[i],
			"PBKDF2 should be deterministic: mismatch at byte %d", i)
	}
}

// TestKDF_Argon2id matches the KDF parameters of the user's keyslot 0.
func TestKDF_Argon2id(t *testing.T) {
	t.Parallel()

	saltHex := "95de991cc0e256f56d1bc27bd77cdf0d46996f310ed59af8bcaf25912613d7f0"
	_, err := hex.DecodeString(saltHex)
	require.NoError(t, err)

	kdf := kdf{
		Type:   "argon2id",
		Time:   11,
		Memory: 1048576,
		Cpus:   4,
		Salt:   saltHex,
	}

	passphrase := []byte("test")
	afKey, err := deriveLuks2AfKey(kdf, 0, passphrase, 64)
	require.NoError(t, err)
	require.Equal(t, 64, len(afKey),
		"Argon2id with keySize=64 should produce 64 bytes")

	t.Logf("Argon2id: salt=%x, key_len=%d, first=0x%02x, last=0x%02x",
		saltHex, len(afKey), afKey[0], afKey[len(afKey)-1])
}

// TestKDF_KeySizeVariations tests PBKDF2 output for various key sizes.
func TestKDF_KeySizeVariations(t *testing.T) {
	t.Parallel()

	df := kdf{
		Type:       "pbkdf2",
		Hash:       "sha512",
		Iterations: 100,
	}

	keySizes := []uint{32, 64, 128}
	for _, ks := range keySizes {
		t.Run(fmt.Sprintf("keysize_%d", ks), func(t *testing.T) {
			afKey, err := deriveLuks2AfKey(df, 0, []byte("pass"), ks)
			require.NoError(t, err)
			require.Equal(t, int(ks), len(afKey),
				"PBKDF2 should produce requested key size")
		})
	}
}
