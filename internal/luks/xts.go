package luks

import "crypto/cipher"

func xtsDecryptSector(block cipher.Block, dst, src []byte, tweak [16]byte) {
	processXTS(block, dst, src, tweak, false)
}

func xtsEncryptSector(block cipher.Block, dst, src []byte, tweak [16]byte) {
	processXTS(block, dst, src, tweak, true)
}

func processXTS(block cipher.Block, dst, src []byte, tweak [16]byte, encrypt bool) {
	T := tweak

	for i := 0; i < len(src); i += 16 {
		for j := 0; j < 16; j++ {
			dst[i+j] = src[i+j] ^ T[j]
		}
		if encrypt {
			block.Encrypt(dst[i:i+16], dst[i:i+16])
		} else {
			block.Decrypt(dst[i:i+16], dst[i:i+16])
		}
		for j := 0; j < 16; j++ {
			dst[i+j] ^= T[j]
		}
		T = gfMul2(T)
	}
}

func gfMul2(x [16]byte) [16]byte {
	var r [16]byte
	var carryIn byte
	for j := 0; j < 16; j++ {
		carryOut := x[j] >> 7
		r[j] = (x[j] << 1) | carryIn
		carryIn = carryOut
	}
	if carryIn != 0 {
		r[0] ^= 0x87
	}
	return r
}
