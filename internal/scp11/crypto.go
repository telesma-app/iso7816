// Package scp11 implements the cryptographic mechanisms used by SCP11b.
package scp11

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
)

// Keys contains caller-owned AES-128 session keys. The slices share the key
// derivation buffer and have capacity limited to their own 16-byte segments.
type Keys struct {
	ENC  []byte
	MAC  []byte
	RMAC []byte
}

// Clear erases the session keys. The separately returned receipt key belongs
// to its caller and is not affected.
func (keys Keys) Clear() {
	clear(keys.ENC)
	clear(keys.MAC)
	clear(keys.RMAC)
}

// DeriveKeys applies the SCP11b X9.63/SHA-256 KDF to Ze || Zs, where Ze and Zs
// are the host's ECDH results with the card's ephemeral and static keys. Each
// hash input is Ze || Zs || counter32BE || 3C 88 10, with counter starting at 1.
// The 80-byte output contains the receipt key, ENC, MAC, RMAC, and an unused DEK.
// The unused DEK is cleared before returning; the inputs are borrowed unchanged.
func DeriveKeys(ephemeralZ, staticZ []byte) (receiptKey []byte, keys Keys) {
	material := make([]byte, 80)
	h := sha256.New()

	var (
		counter [4]byte
		digest  [sha256.Size]byte
	)

	defer clear(digest[:])

	for i := uint32(1); i <= 3; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		h.Reset()
		_, _ = h.Write(ephemeralZ)
		_, _ = h.Write(staticZ)
		_, _ = h.Write(counter[:])
		_, _ = h.Write([]byte{0x3c, 0x88, 0x10})
		sum := h.Sum(digest[:0])
		copy(material[int(i-1)*sha256.Size:], sum)
		clear(sum)
	}

	clear(material[64:])

	return material[:16:16], Keys{
		ENC:  material[16:32:32],
		MAC:  material[32:48:48],
		RMAC: material[48:64:64],
	}
}

// CMAC computes the full 16-byte AES-CMAC from NIST SP 800-38B. Key and message
// are borrowed unchanged. Callers supply a valid AES key derived by SCP11b.
func CMAC(key, message []byte) [aes.BlockSize]byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var subkey, state, last [aes.BlockSize]byte

	defer clear(subkey[:])
	defer clear(state[:])
	defer clear(last[:])

	block.Encrypt(subkey[:], subkey[:])
	cmacDouble(&subkey)

	complete := len(message) != 0 && len(message)%aes.BlockSize == 0
	fullLength := len(message) / aes.BlockSize * aes.BlockSize

	if complete {
		fullLength -= aes.BlockSize
	} else {
		cmacDouble(&subkey)
	}

	for offset := 0; offset < fullLength; offset += aes.BlockSize {
		for i := range state {
			state[i] ^= message[offset+i]
		}

		block.Encrypt(state[:], state[:])
	}

	tail := message[fullLength:]
	copy(last[:], tail)

	if !complete {
		last[len(tail)] = 0x80
	}

	for i := range state {
		state[i] ^= last[i] ^ subkey[i]
	}

	block.Encrypt(state[:], state[:])

	return state
}

func cmacDouble(value *[aes.BlockSize]byte) {
	carry := value[0] >> 7
	for i := range len(value) - 1 {
		value[i] = value[i]<<1 | value[i+1]>>7
	}

	value[len(value)-1] = value[len(value)-1]<<1 ^ (0x87 & (byte(0) - carry))
}
