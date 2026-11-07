package scp11

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/telesma-app/iso7816"
)

func recordBytes(t testing.TB, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}

func recordSession(encoding iso7816.Encoding) (*Session, Keys) {
	keys := Keys{ENC: make([]byte, 16), MAC: make([]byte, 16), RMAC: make([]byte, 16)}

	var receipt [16]byte

	for i := range receipt {
		keys.ENC[i] = byte(i)
		keys.MAC[i] = byte(i + 16)
		keys.RMAC[i] = byte(i + 32)
		receipt[i] = byte(i + 48)
	}

	return NewSession(keys, receipt, encoding), keys
}

// The fixed record vectors below were independently generated with OpenSSL
// 3.5.9: enc -aes-128-ecb/-aes-128-cbc -nopad and dgst -mac cmac. The ENC,
// MAC, RMAC, and initial receipt bytes are respectively 00..0f, 10..1f,
// 20..2f, and 30..3f. The wire rules follow Yubico's ScpState/ScpProcessor.
func TestRecordOpenSSLSequence(t *testing.T) {
	session, _ := recordSession(iso7816.EncodingShort)
	t.Cleanup(session.Clear)

	command := iso7816.Command{
		INS: 0x20, P2: 0x80, Data: []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff}, Encoding: iso7816.EncodingShort,
	}

	wrapped, next, err := session.Protect(command)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	want := recordBytes(t, "042000801860375935e314e1ba1c701648343dbc385980b533c464b436")
	if !bytes.Equal(encoded, want) {
		t.Errorf("first protected command = %x, want %x", encoded, want)
	}

	if want := recordBytes(t, "5980b533c464b436e94f5e8653b56d25"); !bytes.Equal(next[:], want) {
		t.Errorf("first full MAC = %x, want %x", next, want)
	}

	response, err := session.Unprotect(iso7816.Response{
		Data:   recordBytes(t, "f59bf7b418ad985ca2c038948a5aff4e924cca8ef28470595f7da643e61cb49d4e765fb38e90818c"),
		Status: 0x9000,
	}, next)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response.Data, []byte("certificate bytes")) || response.Status != 0x9000 {
		t.Errorf("decoded response = %x, %s", response.Data, response.Status)
	}

	wrapped, next, err = session.Protect(iso7816.Command{CLA: 0x80, INS: 0xfd, P1: 1, P2: 2, Le: 256})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err = wrapped.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	want = recordBytes(t, "84fd010218add7c38c973c10bacced134615c5f69b8f1fa65ad46bef2600")
	if !bytes.Equal(encoded, want) {
		t.Errorf("second protected command = %x, want %x", encoded, want)
	}

	response, err = session.Unprotect(iso7816.Response{
		Data: recordBytes(t, "8851e703ebdd3c48"), Status: 0x6982,
	}, next)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Data) != 0 || response.Status != 0x6982 || session.counter != 3 || session.chain != next {
		t.Errorf("authenticated rejection = %x, %s, counter %d", response.Data, response.Status, session.counter)
	}

	// This command needs extended canonical Lc (0x0108), even when a transport
	// later fragments the protected body into short APDUs.
	data := make([]byte, 240)
	for i := range data {
		data[i] = byte(i)
	}

	wrapped, next, err = session.Protect(iso7816.Command{INS: 0xdb, P1: 0x3f, P2: 0xff, Data: data})
	if err != nil {
		t.Fatal(err)
	}

	want = recordBytes(t, "8c73153893a90e13fd05e84aa4bf24e38dcba3dec7b27290e785990a3854bf8c397acd229aa7b86f197f11e357508b12af14af0d8158a74af3c8ca5594a117341fa66f54363f62b981a5178050780bf6f2a9ad97260304bfd689b1417116f6150879e1aee1b719327497cf840242da06bbd0d88429d3167bb7b04441cf177031f61960d533cd3578d32e5aa4239483680fc0f7d693eeeae08dfe70a7fa0b8f91e7ccbb8f9df0ec0e3afd251ac6ac94268bca0371b6e2446088d9358ecbd33d519539e7e4ae7d1e312d4cac5dc8f864d2cf3a551a13c59fa83d79df812fd45b89521a2c93b2a767f466fa03da8b4d5e0c97c3ee180d435ece26d512367f0fa370b4cd9264f23e1421")
	if !bytes.Equal(wrapped.Data, want) || !bytes.Equal(next[:], recordBytes(t, "b4cd9264f23e14210dba4c939115609f")) {
		t.Errorf("long command encoding or MAC differs: %x, %x", wrapped.Data, next)
	}
}

func TestProtectDoesNotCommitOrChangeCallerInput(t *testing.T) {
	session, _ := recordSession(iso7816.EncodingShort)
	t.Cleanup(session.Clear)
	beforeChain := session.chain
	data := []byte{1, 2, 3}
	command := iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Data: data, Le: 256}

	first, firstMAC, err := session.Protect(command)
	if err != nil {
		t.Fatal(err)
	}

	second, secondMAC, err := session.Protect(command)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.Data, second.Data) || firstMAC != secondMAC || session.chain != beforeChain || session.counter != 1 {
		t.Error("Protect changed the session before an authenticated response")
	}

	if !bytes.Equal(data, []byte{1, 2, 3}) || command.CLA != 0 {
		t.Error("Protect changed the caller's command")
	}

	command.Le = 0

	withoutLe, withoutLeMAC, err := session.Protect(command)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.Data, withoutLe.Data) || firstMAC != withoutLeMAC || first.Le != 256 || withoutLe.Le != 0 {
		t.Error("Le was included in the MAC or was not preserved for transport")
	}
}

func TestExtendedProfileUsesExtendedLCForShortCommands(t *testing.T) {
	session, _ := recordSession(iso7816.EncodingExtended)
	t.Cleanup(session.Clear)

	command := iso7816.Command{
		INS: 0x20, P2: 0x80, Data: []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff}, Encoding: iso7816.EncodingShort,
	}

	wrapped, next, err := session.Protect(command)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Independently generated with the OpenSSL procedure described above,
	// using canonical header 04 20 00 80 00 00 18 rather than short Lc 18.
	want := recordBytes(t, "0420008000001860375935e314e1ba1c701648343dbc38e4dc569d94b71197")
	if !bytes.Equal(encoded, want) || wrapped.Encoding != iso7816.EncodingExtended {
		t.Errorf("extended command = %x, encoding %v; want %x", encoded, wrapped.Encoding, want)
	}

	if want := recordBytes(t, "e4dc569d94b71197bbd0642c1b7d8b5b"); !bytes.Equal(next[:], want) {
		t.Errorf("extended command MAC = %x, want %x", next, want)
	}

	response, err := session.Unprotect(iso7816.Response{
		Data: recordBytes(t, "f59bf7b418ad985ca2c038948a5aff4e924cca8ef28470595f7da643e61cb49d2d70b57452551857"), Status: 0x9000,
	}, next)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response.Data, []byte("certificate bytes")) || session.counter != 2 {
		t.Errorf("extended response = %x, counter %d", response.Data, session.counter)
	}
}

func TestRecordRejectsUnauthenticatedAndMalformedResponsesWithoutCommit(t *testing.T) {
	valid := "f59bf7b418ad985ca2c038948a5aff4e924cca8ef28470595f7da643e61cb49d4e765fb38e90818c"
	for _, tc := range []struct {
		name   string
		data   string
		status iso7816.StatusWord
	}{
		{name: "missing RMAC", status: 0x9000},
		{name: "plain error without RMAC", status: 0x6982},
		{name: "short RMAC", data: "01020304050607", status: 0x9000},
		{name: "tampered RMAC", data: valid[:len(valid)-2] + "00", status: 0x9000},
		{name: "tampered status", data: valid, status: 0x6982},
		{name: "missing padding marker", data: "9077dc065eb4fa194294a3f86f0f89676536882ce7424ae3", status: 0x9000},
		{name: "padding exceeds block", data: "bd2c9955e23f9f73f8e81d896c5193d7933384ff4365085902491cc737b883a3cffdd6d4a782369e", status: 0x9000},
		{name: "wrong padding marker", data: "e7b71f118929441ec4099664758b51d2c76f286a3652a1bd", status: 0x9000},
		{name: "authenticated short ciphertext", data: "016ef93ec08da1aeea", status: 0x9000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, _ := recordSession(iso7816.EncodingShort)
			t.Cleanup(session.Clear)
			beforeChain := session.chain
			next := [16]byte(recordBytes(t, "5980b533c464b436e94f5e8653b56d25"))

			response, err := session.Unprotect(iso7816.Response{Data: recordBytes(t, tc.data), Status: tc.status}, next)
			if !errors.Is(err, iso7816.ErrInvalidResponse) || response.Data != nil {
				t.Fatalf("Unprotect = %x, %v; want invalid response without plaintext", response.Data, err)
			}

			if session.counter != 1 || session.chain != beforeChain {
				t.Error("invalid response committed the counter or MAC chain")
			}
		})
	}
}

func TestRecordAuthenticatesEmptyResponse(t *testing.T) {
	session, _ := recordSession(iso7816.EncodingShort)
	t.Cleanup(session.Clear)
	next := [16]byte(recordBytes(t, "5980b533c464b436e94f5e8653b56d25"))

	response, err := session.Unprotect(iso7816.Response{Data: recordBytes(t, "4acd835243ba278e"), Status: 0x9000}, next)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Data) != 0 || response.Status != 0x9000 || session.counter != 2 || session.chain != next {
		t.Errorf("empty response = %+v, counter %d", response, session.counter)
	}
}

func TestProtectRejectsUnsupportedCommandsWithoutCommit(t *testing.T) {
	for _, command := range []iso7816.Command{
		{CLA: 0x01, INS: 0xcb},
		{CLA: 0x04, INS: 0xcb},
		{CLA: 0x0c, INS: 0xcb},
		{CLA: 0x10, INS: 0xcb},
		{CLA: 0x84, INS: 0xcb},
		{INS: 0xa4},
		{INS: 0xc0},
		{INS: 0xcb, Le: 65536},
		{INS: 0xdb, Data: make([]byte, 65520)},
	} {
		session, _ := recordSession(iso7816.EncodingShort)
		before := session.chain

		if _, _, err := session.Protect(command); !errors.Is(err, iso7816.ErrInvalidCommand) {
			t.Errorf("Protect(%02x,%02x) = %v, want invalid command", command.CLA, command.INS, err)
		}

		if session.chain != before || session.counter != 1 {
			t.Error("invalid command committed the MAC or counter")
		}

		session.Clear()
	}
}

func TestRecordCounterExhaustionClearsKeysBeforeReuse(t *testing.T) {
	session, keys := recordSession(iso7816.EncodingShort)
	session.counter = math.MaxUint64

	_, next, err := session.Protect(iso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil {
		t.Fatal(err)
	}

	macInput := append(append([]byte(nil), next[:]...), 0x90, 0)
	responseMAC := CMAC(keys.RMAC, macInput)

	if _, err := session.Unprotect(iso7816.Response{Data: responseMAC[:8], Status: 0x9000}, next); err != nil {
		t.Fatal(err)
	}

	if session.counter != 0 || session.enc != nil || session.chain != [16]byte{} {
		t.Error("exhausted session retained active state")
	}

	for _, key := range [][]byte{keys.ENC, keys.MAC, keys.RMAC} {
		if !bytes.Equal(key, make([]byte, len(key))) {
			t.Error("exhausted session did not clear owned key bytes")
		}
	}

	if _, _, err := session.Protect(iso7816.Command{INS: 0x20}); !errors.Is(err, iso7816.ErrInvalidCommand) {
		t.Errorf("Protect after counter exhaustion = %v, want rejection", err)
	}
}
