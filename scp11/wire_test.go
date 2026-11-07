package scp11

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
)

func scp11Point(t testing.TB) []byte {
	t.Helper()

	// SEC 2's P-256 base point, in uncompressed SEC 1 encoding.
	point, err := hex.DecodeString("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}

	return point
}

func TestSCP11bAuthenticateCommandWire(t *testing.T) {
	point := scp11Point(t)
	command := internalAuthenticateCommand(0x02, 0x13, point)

	encoded, err := command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{
		0x80, 0x88, 0x02, 0x13, 0x53,
		0xa6, 0x0d, 0x90, 0x02, 0x11, 0x00, 0x95, 0x01, 0x3c,
		0x80, 0x01, 0x88, 0x81, 0x01, 0x10, 0x5f, 0x49, 0x41,
	}
	want = append(want, point...)
	want = append(want, 0x00)

	if !bytes.Equal(encoded, want) {
		t.Errorf("INTERNAL AUTHENTICATE = %x, want %x", encoded, want)
	}

	if command.Encoding != iso7816.EncodingShort || command.Le != 256 {
		t.Errorf("encoding/Le = %v/%d, want short/256", command.Encoding, command.Le)
	}

	command.Data[len(command.Data)-1] ^= 1

	if !bytes.Equal(point, scp11Point(t)) {
		t.Error("command encoding borrowed and changed caller's public key")
	}
}

func TestParseSCP11bResponse(t *testing.T) {
	point := scp11Point(t)
	receipt := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	data := append([]byte{0x5f, 0x49, 0x41}, point...)
	data = append(data, 0x86, 0x10)
	data = append(data, receipt[:]...)

	gotPoint, gotReceipt, err := parseInternalAuthenticateResponse(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(gotPoint, point) || gotReceipt != receipt {
		t.Errorf("SCP11b response = %x/%x, want %x/%x", gotPoint, gotReceipt, point, receipt)
	}

	gotPoint[1] ^= 1
	data[len(data)-1] ^= 1

	if gotPoint[1] != data[4] {
		t.Error("parsed public key does not borrow response bytes")
	}

	if gotReceipt != receipt {
		t.Error("receipt does not have value semantics")
	}
}

func TestParseSCP11bResponseRejectsMalformedData(t *testing.T) {
	point := scp11Point(t)
	key := append([]byte{0x5f, 0x49, 0x41}, point...)
	valid := append(bytes.Clone(key), 0x86, 0x10)
	valid = append(valid, make([]byte, 16)...)
	invalidPoint := append([]byte{0x5f, 0x49, 0x41, 0x04}, make([]byte, 64)...)
	invalidPoint = append(invalidPoint, 0x86, 0x10)
	invalidPoint = append(invalidPoint, make([]byte, 16)...)
	compressedPoint := append([]byte{0x5f, 0x49, 0x21, 0x03}, point[1:33]...)
	compressedPoint = append(compressedPoint, 0x86, 0x10)
	compressedPoint = append(compressedPoint, make([]byte, 16)...)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "wrong first tag", data: []byte{0x86, 0x10, 0}},
		{name: "truncated public key", data: []byte{0x5f, 0x49, 0x41, 0x04}},
		{name: "empty public key", data: []byte{0x5f, 0x49, 0}},
		{name: "compressed point", data: compressedPoint},
		{name: "point outside curve", data: invalidPoint},
		{name: "missing receipt", data: key},
		{name: "wrong receipt tag", data: append(bytes.Clone(key), 0x87, 0x00)},
		{name: "short receipt", data: append(bytes.Clone(key), 0x86, 0x01, 0)},
		{name: "truncated receipt", data: valid[:len(valid)-1]},
		{name: "duplicate public key", data: append(bytes.Clone(key), valid...)},
		{name: "duplicate receipt", data: append(bytes.Clone(valid), 0x86, 0)},
		{name: "trailing byte", data: append(bytes.Clone(valid), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotPoint, gotReceipt, err := parseInternalAuthenticateResponse(tc.data)
			if !errors.Is(err, iso7816.ErrInvalidResponse) || gotPoint != nil || gotReceipt != [16]byte{} {
				t.Errorf("parseInternalAuthenticateResponse = %x/%x, %v; want invalid response", gotPoint, gotReceipt, err)
			}
		})
	}
}
