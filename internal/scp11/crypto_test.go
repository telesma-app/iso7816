package scp11

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func cryptoBytes(t testing.TB, text string) []byte {
	t.Helper()

	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}

	return value
}

func TestCMACKnownAnswers(t *testing.T) {
	// NIST AES-CMAC Examples (AES_CMAC.pdf), Examples 1-4 for AES-128 and
	// AES-256. The message is truncated to the specified length so the same
	// input covers empty, partial, and full final blocks.
	message := cryptoBytes(t,
		"6bc1bee22e409f96e93d7e117393172a"+
			"ae2d8a571e03ac9c9eb76fac45af8e51"+
			"30c81c46a35ce411e5fbc1191a0a52ef"+
			"f69f2445df4f9b17ad2b417be66c3710",
	)

	for _, tc := range []struct {
		name   string
		key    string
		length int
		mac    string
	}{
		{name: "AES-128 empty", key: "2b7e151628aed2a6abf7158809cf4f3c", mac: "bb1d6929e95937287fa37d129b756746"},
		{name: "AES-128 one block", key: "2b7e151628aed2a6abf7158809cf4f3c", length: 16, mac: "070a16b46b4d4144f79bdd9dd04a287c"},
		{name: "AES-128 partial final block", key: "2b7e151628aed2a6abf7158809cf4f3c", length: 20, mac: "7d85449ea6ea19c823a7bf78837dfade"},
		{name: "AES-128 four blocks", key: "2b7e151628aed2a6abf7158809cf4f3c", length: 64, mac: "51f0bebf7e3b9d92fc49741779363cfe"},
		{name: "AES-256 empty", key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", mac: "028962f61b7bf89efc6b551f4667d983"},
		{name: "AES-256 one block", key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", length: 16, mac: "28a7023f452e8f82bd4bf28d8c37c35c"},
		{name: "AES-256 partial final block", key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", length: 20, mac: "156727dc0878944a023c1fe03bad6d93"},
		{name: "AES-256 four blocks", key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", length: 64, mac: "e1992190549f6ed5696a2c056c315410"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := cryptoBytes(t, tc.key)
			originalKey := bytes.Clone(key)
			originalMessage := bytes.Clone(message)

			got := CMAC(key, message[:tc.length])

			if !bytes.Equal(got[:], cryptoBytes(t, tc.mac)) {
				t.Errorf("CMAC = %x, want %s", got, tc.mac)
			}

			if !bytes.Equal(key, originalKey) || !bytes.Equal(message, originalMessage) {
				t.Error("CMAC changed borrowed input")
			}
		})
	}
}

func TestDeriveKeysIndependentReference(t *testing.T) {
	// Independent reference: Python hashlib.sha256 computes Ze || Zs ||
	// counter32BE || 3c8810 for counters 1, 2, 3. The first 80 bytes match
	// the SCP11b X963KDF used by Yubico's yubikit/core/smartcard/scp.py and
	// TOKEN2's token2-piv-tool/lib/t2piv.c, scp11_derive_session_keys.
	ephemeral := cryptoBytes(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	static := cryptoBytes(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	originalEphemeral := bytes.Clone(ephemeral)
	originalStatic := bytes.Clone(static)

	receipt, keys := DeriveKeys(ephemeral, static)
	defer clear(receipt)
	defer keys.Clear()

	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{name: "receipt", got: receipt, want: "78e6afba798e338b0b6104dfc18e5b9e"},
		{name: "ENC", got: keys.ENC, want: "faabdf39c991de6879d9c7a0c21ff022"},
		{name: "MAC", got: keys.MAC, want: "40998ce38b6d3dd3fd3fa9c7d956b673"},
		{name: "RMAC", got: keys.RMAC, want: "23d069af6457586600431b7ec83d38c7"},
	} {
		if !bytes.Equal(tc.got, cryptoBytes(t, tc.want)) {
			t.Errorf("%s = %x, want %s", tc.name, tc.got, tc.want)
		}

		if len(tc.got) != 16 || cap(tc.got) != 16 {
			t.Errorf("%s length/capacity = %d/%d, want 16/16", tc.name, len(tc.got), cap(tc.got))
		}
	}

	if !bytes.Equal(ephemeral, originalEphemeral) || !bytes.Equal(static, originalStatic) {
		t.Error("key derivation changed borrowed ECDH secrets")
	}

	originalMAC := bytes.Clone(keys.MAC)
	_ = append(keys.ENC, 0xff)

	if !bytes.Equal(keys.MAC, originalMAC) {
		t.Error("appending to ENC overwrote the adjacent MAC key")
	}
}

func TestReceiptIndependentReference(t *testing.T) {
	// Using the independently derived receipt key above, OpenSSL computes:
	// openssl dgst -mac cmac -macopt cipher:aes-128-cbc \
	//   -macopt hexkey:78e6afba798e338b0b6104dfc18e5b9e
	// The transcript is the exact INTERNAL AUTHENTICATE request data followed
	// by the encoded 5F49 card ephemeral point. Point bytes are opaque to CMAC.
	key := cryptoBytes(t, "78e6afba798e338b0b6104dfc18e5b9e")
	transcript := cryptoBytes(t,
		"a60d9002110095013c800188810110"+
			"5f494104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"+
			"5f494104404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
	)

	got := CMAC(key, transcript)
	want := cryptoBytes(t, "4be061229ab5ff488d4e322e48d5e2b6")

	if !bytes.Equal(got[:], want) {
		t.Errorf("receipt CMAC = %x, want %x", got, want)
	}
}

func TestKeysClearErasesSessionKeysOnly(t *testing.T) {
	ephemeral := cryptoBytes(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	static := cryptoBytes(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

	receipt, keys := DeriveKeys(ephemeral, static)
	defer clear(receipt)

	originalReceipt := bytes.Clone(receipt)

	keys.Clear()

	for _, key := range [][]byte{keys.ENC, keys.MAC, keys.RMAC} {
		if !bytes.Equal(key, make([]byte, 16)) {
			t.Errorf("session key was not cleared: %x", key)
		}
	}

	if !bytes.Equal(receipt, originalReceipt) {
		t.Error("clearing session keys also changed the caller-owned receipt key")
	}
}
