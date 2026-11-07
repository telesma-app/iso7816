package scp11

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/telesma-app/iso7816"
)

// Session protects complete SCP11 logical commands and responses. The owning
// transport serializes Protect, Unprotect, and Clear, including against Close.
// Chaining and GET RESPONSE happen outside this codec, after Protect and before
// Unprotect. No plaintext fallback is supported.
type Session struct {
	keys     Keys
	enc      cipher.Block
	chain    [16]byte
	counter  uint64
	encoding iso7816.Encoding
}

// NewSession takes ownership of derived keys. The verified handshake receipt
// initializes the command MAC chain. Keys must contain valid AES key material;
// encoding must be EncodingShort or EncodingExtended as selected by the owner.
func NewSession(keys Keys, receipt [16]byte, encoding iso7816.Encoding) *Session {
	enc, err := aes.NewCipher(keys.ENC)
	if err != nil {
		panic(err)
	}

	return &Session{keys: keys, enc: enc, chain: receipt, counter: 1, encoding: encoding}
}

// Protect encrypts and authenticates a complete command without changing session
// state. The returned MAC is committed by Unprotect only after an authenticated
// response, preserving state when cancellation prevents transmission.
func (s *Session) Protect(command iso7816.Command) (iso7816.Command, [16]byte, error) {
	if s.counter == 0 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: SCP11 encryption counter exhausted", iso7816.ErrInvalidCommand)
	}

	if command.CLA != 0 && command.CLA != 0x80 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: unsupported SCP11 CLA %02x", iso7816.ErrInvalidCommand, command.CLA)
	}

	if command.INS == 0xa4 || command.INS == 0xc0 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: SCP11 application selection and manual GET RESPONSE are unsupported", iso7816.ErrInvalidCommand)
	}

	if command.Le > 256 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: SCP11 short response Le exceeds 256", iso7816.ErrInvalidCommand)
	}

	// Canonical MAC input contains the full encrypted-data length plus its MAC,
	// even when short APDUs will subsequently fragment the command.
	if len(command.Data) > 65519 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: SCP11 command data is too large", iso7816.ErrInvalidCommand)
	}

	paddingLength := aes.BlockSize - len(command.Data)%aes.BlockSize
	encrypted := make([]byte, len(command.Data)+paddingLength, len(command.Data)+paddingLength+8)
	copy(encrypted, command.Data)
	encrypted[len(command.Data)] = 0x80
	iv := s.iv(false)
	cipher.NewCBCEncrypter(s.enc, iv[:]).CryptBlocks(encrypted, encrypted)

	command.CLA |= 0x04

	macInput := append([]byte(nil), s.chain[:]...)
	macInput = append(macInput, command.CLA, command.INS, command.P1, command.P2)
	lc := len(encrypted) + 8

	if s.encoding == iso7816.EncodingShort && lc <= 255 {
		macInput = append(macInput, byte(lc))
	} else {
		macInput = append(macInput, 0, byte(lc>>8), byte(lc))
	}

	macInput = append(macInput, encrypted...)
	next := CMAC(s.keys.MAC, macInput)
	command.Data = append(encrypted, next[:8]...)
	command.Encoding = s.encoding

	return command, next, nil
}

// Unprotect authenticates before decrypting. An authenticated APDU rejection is
// returned as a normal response, preserving the channel. Missing RMAC, invalid
// ciphertext, and invalid padding match iso7816.ErrInvalidResponse. On any
// error the owning transport must invalidate the connection; no state commits.
func (s *Session) Unprotect(response iso7816.Response, next [16]byte) (iso7816.Response, error) {
	if len(response.Data) < 8 {
		return iso7816.Response{}, fmt.Errorf("%w: SCP11 response MAC is missing (unauthenticated SW=%s)", iso7816.ErrInvalidResponse, response.Status)
	}

	ciphertext := response.Data[:len(response.Data)-8]

	macInput := append([]byte(nil), next[:]...)
	macInput = append(macInput, ciphertext...)
	macInput = append(macInput, response.Status.SW1(), response.Status.SW2())
	expected := CMAC(s.keys.RMAC, macInput)

	if subtle.ConstantTimeCompare(expected[:8], response.Data[len(ciphertext):]) != 1 {
		return iso7816.Response{}, fmt.Errorf("%w: invalid SCP11 response MAC", iso7816.ErrInvalidResponse)
	}

	var plaintext []byte

	if len(ciphertext) != 0 {
		if len(ciphertext)%aes.BlockSize != 0 {
			return iso7816.Response{}, fmt.Errorf("%w: invalid SCP11 ciphertext length", iso7816.ErrInvalidResponse)
		}

		plaintext = make([]byte, len(ciphertext))
		iv := s.iv(true)
		cipher.NewCBCDecrypter(s.enc, iv[:]).CryptBlocks(plaintext, ciphertext)
		padding := len(plaintext) - 1

		for padding >= 0 && plaintext[padding] == 0 {
			padding--
		}

		if padding < 0 || plaintext[padding] != 0x80 || len(plaintext)-padding > aes.BlockSize {
			clear(plaintext)
			return iso7816.Response{}, fmt.Errorf("%w: invalid SCP11 response padding", iso7816.ErrInvalidResponse)
		}

		clear(plaintext[padding:])
		plaintext = plaintext[:padding:padding]
	}

	s.chain = next
	if s.counter == math.MaxUint64 {
		s.Clear()
	} else {
		s.counter++
	}

	return iso7816.Response{Data: plaintext, Status: response.Status}, nil
}

func (s *Session) iv(response bool) [16]byte {
	var counter, iv [16]byte
	if response {
		counter[0] = 0x80
	}

	binary.BigEndian.PutUint64(counter[8:], s.counter)
	s.enc.Encrypt(iv[:], counter[:])

	return iv
}

// Clear erases owned key bytes, counter, and MAC state and drops the expanded
// AES key. It must not run concurrently with Protect or Unprotect.
func (s *Session) Clear() {
	s.keys.Clear()
	s.enc = nil
	s.counter = 0
	clear(s.chain[:])
}
