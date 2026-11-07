package scp11

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	cryptoscp "github.com/telesma-app/iso7816/internal/scp11"
)

// channelPeer independently implements the card side of the SCP11b wire format.
// It shares only AES-CMAC with the implementation; that primitive has independent
// known-answer tests. KDF, CBC records, counters, and APDU headers are checked here.
type channelPeer struct {
	t             testing.TB
	static        *ecdh.PrivateKey
	ephemeral     *ecdh.PrivateKey
	requests      []iso7816.Command
	plaintext     []iso7816.Command
	authStatus    iso7816.StatusWord
	handshake     func([]byte) []byte
	response      func(iso7816.Response) iso7816.Response
	beforeRecord  func(context.Context) error
	afterResponse func()
	effect        func(iso7816.Command) iso7816.Response
	phase         int
	keys          [4][16]byte
	chain         [16]byte
	counter       uint64
	closed        chan struct{}
	finishClose   chan struct{}
	closeCalls    int
	closeErr      error
}

func peerPrivateKey(t testing.TB, curve ecdh.Curve, scalar byte) *ecdh.PrivateKey {
	t.Helper()

	width := 32
	if curve == ecdh.P384() {
		width = 48
	}

	encoded := make([]byte, width)
	encoded[len(encoded)-1] = scalar

	key, err := curve.NewPrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func newChannelPeer(t testing.TB) *channelPeer {
	t.Helper()
	peer := &channelPeer{
		t: t, static: peerPrivateKey(t, ecdh.P256(), 1), ephemeral: peerPrivateKey(t, ecdh.P256(), 2),
		closed: make(chan struct{}),
	}
	t.Cleanup(func() {
		select {
		case <-peer.closed:
		default:
			_ = peer.Close()
		}
	})

	return peer
}

func channelParameters(peer *channelPeer, encoding iso7816.Encoding) Parameters {
	return Parameters{KeyID: 0x13, KeyVersion: 1, PeerKey: peer.static.PublicKey(), Encoding: encoding}
}

func openPeer(t testing.TB, peer *channelPeer, encoding iso7816.Encoding) *Transport {
	t.Helper()

	connection, err := Open(t.Context(), peer, channelParameters(peer, encoding))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	return connection
}

func (peer *channelPeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	peer.t.Helper()

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	select {
	case <-peer.closed:
		return iso7816.Response{}, &iso7816.DeviceInvalidatedError{Err: io.ErrClosedPipe}
	default:
	}

	if peer.phase == 1 && peer.beforeRecord != nil {
		if err := peer.beforeRecord(ctx); err != nil {
			return iso7816.Response{}, err
		}
	}

	snapshot := command
	snapshot.Data = bytes.Clone(command.Data)
	peer.requests = append(peer.requests, snapshot)

	if peer.phase == 0 {
		return peer.authenticate(command)
	}

	return peer.exchangeRecord(command)
}

func (peer *channelPeer) authenticate(command iso7816.Command) (iso7816.Response, error) {
	peer.t.Helper()

	prefix := []byte{0xa6, 13, 0x90, 2, 0x11, 0, 0x95, 1, 0x3c, 0x80, 1, 0x88, 0x81, 1, 0x10, 0x5f, 0x49, 65}
	if command.CLA != 0x80 || command.INS != 0x88 || command.P1 != 1 || command.P2 != 0x13 ||
		command.Le != 256 || command.Encoding != iso7816.EncodingShort ||
		len(command.Data) != len(prefix)+65 || !bytes.Equal(command.Data[:len(prefix)], prefix) {
		peer.t.Errorf("unexpected SCP11b authentication: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if peer.authStatus != 0 {
		return iso7816.Response{Status: peer.authStatus}, nil
	}

	host, err := ecdh.P256().NewPublicKey(command.Data[len(prefix):])
	if err != nil {
		peer.t.Error(err)
		return iso7816.Response{}, err
	}

	ze, err := peer.ephemeral.ECDH(host)
	if err != nil {
		peer.t.Error(err)
		return iso7816.Response{}, err
	}

	zs, err := peer.static.ECDH(host)
	if err != nil {
		peer.t.Error(err)
		return iso7816.Response{}, err
	}

	// Independent ANSI X9.63 transcript: Ze || Zs || counter32 || sharedInfo.
	var material []byte
	for counter := uint32(1); len(material) < 80; counter++ {
		input := append(bytes.Clone(ze), zs...)
		input = binary.BigEndian.AppendUint32(input, counter)
		input = append(input, 0x3c, 0x88, 0x10)
		hash := sha256.Sum256(input)
		material = append(material, hash[:]...)
	}

	for i := range peer.keys {
		copy(peer.keys[i][:], material[i*16:(i+1)*16])
	}

	point := peer.ephemeral.PublicKey().Bytes()
	pointTLV := append([]byte{0x5f, 0x49, 65}, point...)
	transcript := append(bytes.Clone(command.Data), pointTLV...)
	receipt := cryptoscp.CMAC(peer.keys[0][:], transcript)
	peer.chain = receipt
	peer.counter = 1
	peer.phase++

	data := append(pointTLV, 0x86, 16)

	data = append(data, receipt[:]...)
	if peer.handshake != nil {
		data = peer.handshake(data)
	}

	return iso7816.Response{Status: 0x9000, Data: data}, nil
}

func (peer *channelPeer) exchangeRecord(command iso7816.Command) (iso7816.Response, error) {
	peer.t.Helper()

	if command.CLA != 0x04 && command.CLA != 0x84 || len(command.Data) < 24 {
		peer.t.Errorf("command was not protected: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	ciphertext := command.Data[:len(command.Data)-8]
	if len(ciphertext)%aes.BlockSize != 0 {
		peer.t.Errorf("command ciphertext length = %d", len(ciphertext))
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	macInput := append(bytes.Clone(peer.chain[:]), command.CLA, command.INS, command.P1, command.P2)
	if command.Encoding == iso7816.EncodingExtended || len(command.Data) > 255 {
		macInput = append(macInput, 0, byte(len(command.Data)>>8), byte(len(command.Data)))
	} else {
		macInput = append(macInput, byte(len(command.Data)))
	}

	macInput = append(macInput, ciphertext...)

	next := cryptoscp.CMAC(peer.keys[2][:], macInput)
	if !bytes.Equal(next[:8], command.Data[len(ciphertext):]) {
		peer.t.Error("command MAC did not match its header, ciphertext, and previous chain")
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	block, err := aes.NewCipher(peer.keys[1][:])
	if err != nil {
		peer.t.Fatal(err)
	}

	var counter, iv [16]byte
	binary.BigEndian.PutUint64(counter[8:], peer.counter)
	block.Encrypt(iv[:], counter[:])

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(plaintext, ciphertext)

	padding := len(plaintext) - 1
	for padding >= 0 && plaintext[padding] == 0 {
		padding--
	}

	if padding < 0 || plaintext[padding] != 0x80 || len(plaintext)-padding > 16 {
		peer.t.Error("command padding was not ISO 7816-4 padding")
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	decoded := command
	decoded.CLA &^= 4
	decoded.Data = plaintext[:padding]
	peer.plaintext = append(peer.plaintext, decoded)

	response := iso7816.Response{Status: 0x9000, Data: []byte{0x53, 3, 1, 2, 3}}
	if peer.effect != nil {
		response = peer.effect(decoded)
	}

	responseCiphertext := []byte(nil)

	if len(response.Data) != 0 {
		length := (len(response.Data)/16 + 1) * 16
		responseCiphertext = make([]byte, length)
		copy(responseCiphertext, response.Data)
		responseCiphertext[len(response.Data)] = 0x80
		counter[0] = 0x80
		block.Encrypt(iv[:], counter[:])
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(responseCiphertext, responseCiphertext)
	}

	macInput = append(bytes.Clone(next[:]), responseCiphertext...)
	macInput = append(macInput, response.Status.SW1(), response.Status.SW2())
	rmac := cryptoscp.CMAC(peer.keys[3][:], macInput)
	response.Data = append(responseCiphertext, rmac[:8]...)
	peer.chain = next

	peer.counter++
	if peer.response != nil {
		response = peer.response(response)
	}

	if peer.afterResponse != nil {
		peer.afterResponse()
	}

	return response, nil
}

func (peer *channelPeer) Close() error {
	peer.closeCalls++
	close(peer.closed)

	if peer.finishClose != nil {
		<-peer.finishClose
	}

	return peer.closeErr
}

func TestOpenSCP11bAndExchangeCommands(t *testing.T) {
	for _, encoding := range []iso7816.Encoding{iso7816.EncodingShort, iso7816.EncodingExtended} {
		t.Run(fmt.Sprint(encoding), func(t *testing.T) {
			peer := newChannelPeer(t)
			peer.effect = func(command iso7816.Command) iso7816.Response {
				if command.INS != 0x5b || command.P1 != 0x10 || command.P2 != 0x20 ||
					!bytes.Equal(command.Data, []byte{0xaa, 0xbb, 0xcc}) {
					t.Errorf("decoded application command = %+v", command)
				}

				return iso7816.Response{Status: 0x9000, Data: []byte{1, 2, 3}}
			}
			secure := openPeer(t, peer, encoding)

			if len(peer.requests) != 1 || peer.requests[0].INS != 0x88 {
				t.Fatalf("Open sent %d commands; want only INTERNAL AUTHENTICATE on the selected application", len(peer.requests))
			}

			for _, cla := range []byte{0, 0x80, 0} {
				response, err := secure.Exchange(t.Context(), iso7816.Command{
					CLA: cla, INS: 0x5b, P1: 0x10, P2: 0x20, Data: []byte{0xaa, 0xbb, 0xcc}, Le: 256,
				})
				if err != nil || response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{1, 2, 3}) {
					t.Fatalf("protected application response = %+v, %v", response, err)
				}
			}

			if len(peer.requests) != 4 || len(peer.plaintext) != 3 || peer.counter != 4 {
				t.Errorf("requests/plaintexts/counter = %d/%d/%d", len(peer.requests), len(peer.plaintext), peer.counter)
			}

			for i, command := range peer.requests[1:] {
				if command.CLA != peer.plaintext[i].CLA|4 || command.Encoding != encoding || bytes.Contains(command.Data, peer.plaintext[i].Data) {
					t.Errorf("protected command %d exposed plaintext or changed profile", i)
				}
			}
		})
	}
}

func TestProtectedVerifyDoesNotExposePIN(t *testing.T) {
	peer := newChannelPeer(t)
	peer.effect = func(command iso7816.Command) iso7816.Response {
		if command.INS != 0x20 || command.P2 != 0x80 ||
			!bytes.Equal(command.Data, []byte{'8', '6', '5', '3', '6', '2', 0xff, 0xff}) {
			t.Errorf("decoded VERIFY = %+v", command)
		}

		return iso7816.Response{Status: 0x9000}
	}
	secure := openPeer(t, peer, iso7816.EncodingShort)

	response, err := secure.Exchange(t.Context(), iso7816.Command{
		INS: 0x20, P2: 0x80, Data: []byte{'8', '6', '5', '3', '6', '2', 0xff, 0xff},
	})
	if err != nil || response.Status != 0x9000 {
		t.Fatalf("protected VERIFY = %+v, %v", response, err)
	}

	if bytes.Contains(peer.requests[1].Data, []byte("865362")) {
		t.Error("protected VERIFY exposed PIN bytes")
	}
}

func TestSCP11bOpenFailuresRetainOrInvalidateOwnership(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*channelPeer, *Parameters)
		invalid   bool
		status    iso7816.StatusWord
		wantNoIO  bool
	}{
		{
			name: "unspecified encoding", wantNoIO: true,
			configure: func(_ *channelPeer, parameters *Parameters) { parameters.Encoding = iso7816.EncodingAuto },
		},
		{name: "unsupported SCP11b", status: 0x6a88, configure: func(peer *channelPeer, _ *Parameters) { peer.authStatus = 0x6a88 }},
		{
			name: "wrong pinned key", invalid: true,
			configure: func(_ *channelPeer, parameters *Parameters) {
				parameters.PeerKey = peerPrivateKey(t, ecdh.P256(), 3).PublicKey()
			},
		},
		{
			name: "wrong receipt", invalid: true,
			configure: func(peer *channelPeer, _ *Parameters) {
				peer.handshake = func(data []byte) []byte { data[len(data)-1] ^= 1; return data }
			},
		},
		{
			name: "malformed response", invalid: true,
			configure: func(peer *channelPeer, _ *Parameters) {
				peer.handshake = func([]byte) []byte { return []byte{0x5f, 0x49, 0} }
			},
		},
		{
			name: "wrong pinned curve", wantNoIO: true,
			configure: func(_ *channelPeer, parameters *Parameters) {
				parameters.PeerKey = peerPrivateKey(t, ecdh.P384(), 1).PublicKey()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newChannelPeer(t)
			parameters := channelParameters(peer, iso7816.EncodingShort)
			tc.configure(peer, &parameters)

			secure, err := Open(t.Context(), peer, parameters)
			if secure != nil || err == nil {
				t.Fatalf("Open = %v, %v; want failure", secure, err)
			}

			var invalidated *iso7816.DeviceInvalidatedError
			if errors.As(err, &invalidated) != tc.invalid {
				t.Errorf("Open invalidation = %v, want %t", err, tc.invalid)
			}

			if tc.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Errorf("Open = %v, want APDU %s", err, tc.status)
				}
			}

			wantCloses := 0
			if tc.invalid {
				wantCloses = 1
			}

			if tc.wantNoIO && len(peer.requests) != 0 || peer.closeCalls != wantCloses {
				t.Errorf("failed Open: requests=%d closes=%d", len(peer.requests), peer.closeCalls)
			}
		})
	}
}

func TestPreCanceledOpenDoesNotTransmitOrClose(t *testing.T) {
	peer := newChannelPeer(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	secure, err := Open(ctx, peer, channelParameters(peer, iso7816.EncodingShort))
	if secure != nil || !errors.Is(err, context.Canceled) || len(peer.requests) != 0 || peer.closeCalls != 0 {
		t.Fatalf("Open = %v, %v, requests=%d closes=%d", secure, err, len(peer.requests), peer.closeCalls)
	}
}

func TestAuthenticatedStatusRejectionKeepsChannel(t *testing.T) {
	peer := newChannelPeer(t)
	status := iso7816.StatusWord(0x6982)
	peer.effect = func(iso7816.Command) iso7816.Response { return iso7816.Response{Status: status} }
	secure := openPeer(t, peer, iso7816.EncodingShort)

	response, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Le: 256})
	if err != nil || response.Status != status || peer.closeCalls != 0 {
		t.Fatalf("authenticated rejection = %+v, %v, closes=%d", response, err, peer.closeCalls)
	}

	status = 0x9000

	if response, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0x20, P2: 0x80}); err != nil || response.Status != 0x9000 {
		t.Fatalf("exchange after authenticated rejection = %+v, %v", response, err)
	}
}

func TestUnauthenticatedResponsesInvalidateChannel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(iso7816.Response) iso7816.Response
	}{
		{name: "missing RMAC", tamper: func(response iso7816.Response) iso7816.Response { response.Data = nil; return response }},
		{name: "wrong RMAC", tamper: func(response iso7816.Response) iso7816.Response {
			response.Data[len(response.Data)-1] ^= 1
			return response
		}},
		{name: "status tampering", tamper: func(response iso7816.Response) iso7816.Response { response.Status = 0x6982; return response }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newChannelPeer(t)
			peer.response = tc.tamper
			secure := openPeer(t, peer, iso7816.EncodingShort)
			closeErr := errors.New("disconnect failed")
			peer.closeErr = closeErr

			_, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb, Le: 256})

			var invalidated *iso7816.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, iso7816.ErrInvalidResponse) || !errors.Is(err, closeErr) || peer.closeCalls != 1 {
				t.Fatalf("Exchange = %v, closes=%d; want invalidation and both causes", err, peer.closeCalls)
			}

			count := len(peer.requests)
			if _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0x20}); !errors.Is(err, io.ErrClosedPipe) || len(peer.requests) != count {
				t.Errorf("Exchange after invalidation = %v; plaintext fallback or reuse occurred", err)
			}
		})
	}
}

func TestAuthenticatedMalformedCiphertextInvalidatesChannel(t *testing.T) {
	for _, malformedPadding := range []bool{false, true} {
		name := "ciphertext length"
		if malformedPadding {
			name = "padding"
		}

		t.Run(name, func(t *testing.T) {
			peer := newChannelPeer(t)
			peer.response = func(response iso7816.Response) iso7816.Response {
				ciphertext := []byte{1}

				if malformedPadding {
					block, err := aes.NewCipher(peer.keys[1][:])
					if err != nil {
						t.Fatal(err)
					}

					var counter, iv [16]byte

					counter[0] = 0x80
					binary.BigEndian.PutUint64(counter[8:], peer.counter-1)
					block.Encrypt(iv[:], counter[:])

					ciphertext = make([]byte, aes.BlockSize)
					cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, ciphertext)
				}

				input := append(bytes.Clone(peer.chain[:]), ciphertext...)
				input = append(input, response.Status.SW1(), response.Status.SW2())
				rmac := cryptoscp.CMAC(peer.keys[3][:], input)
				response.Data = append(ciphertext, rmac[:8]...)

				return response
			}
			secure := openPeer(t, peer, iso7816.EncodingShort)

			_, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb, Le: 256})

			var invalidated *iso7816.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, iso7816.ErrInvalidResponse) || peer.closeCalls != 1 {
				t.Fatalf("malformed authenticated response = %v, closes=%d", err, peer.closeCalls)
			}
		})
	}
}

func TestPreTransmissionCancellationPreservesCounter(t *testing.T) {
	peer := newChannelPeer(t)
	secure := openPeer(t, peer, iso7816.EncodingShort)
	peer.beforeRecord = func(context.Context) error { return context.Canceled }

	if _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb, Le: 256}); !errors.Is(err, context.Canceled) || peer.closeCalls != 0 {
		t.Fatalf("pre-transmission cancellation = %v, closes=%d", err, peer.closeCalls)
	}

	peer.beforeRecord = nil
	if _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb, Le: 256}); err != nil || peer.counter != 2 {
		t.Fatalf("exchange after cancellation = %v, counter=%d", err, peer.counter)
	}
}

func TestLateCancellationPreservesAuthenticatedResponse(t *testing.T) {
	peer := newChannelPeer(t)
	secure := openPeer(t, peer, iso7816.EncodingShort)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	peer.afterResponse = cancel

	response, err := secure.Exchange(ctx, iso7816.Command{INS: 0xcb, Le: 256})
	if err != nil || !bytes.Equal(response.Data, []byte{0x53, 3, 1, 2, 3}) || peer.closeCalls != 0 {
		t.Fatalf("late cancellation replaced response = %+v, %v", response, err)
	}
}

func TestCloseReleasesQueueBeforeUnderlyingCloseFinishes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer := newChannelPeer(t)
		peer.finishClose = make(chan struct{})

		finishClose := sync.OnceFunc(func() { close(peer.finishClose) })
		defer finishClose()

		secure := openPeer(t, peer, iso7816.EncodingShort)
		started := make(chan struct{})
		peer.beforeRecord = func(ctx context.Context) error {
			close(started)

			select {
			case <-peer.closed:
				return &iso7816.DeviceInvalidatedError{Err: io.ErrClosedPipe}
			case <-ctx.Done():
				return &iso7816.DeviceInvalidatedError{Err: ctx.Err()}
			}
		}
		active := make(chan error, 1)

		go func() { _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb}); active <- err }()

		receiveChannel(t, started, "protected exchange did not start")

		queued := make(chan error, 1)

		go func() { _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0x20}); queued <- err }()

		synctest.Wait()

		closed := make(chan error, 1)
		go func() { closed <- secure.Close() }()

		receiveChannel(t, peer.closed, "Close waited for the exchange gate")

		if err := receiveChannel(t, queued, "queued exchange waited for underlying Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("queued Exchange = %v", err)
		}

		finishClose()

		if err := receiveChannel(t, closed, "Close did not finish"); err != nil {
			t.Fatal(err)
		}

		if err := receiveChannel(t, active, "active exchange did not stop"); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("active Exchange = %v", err)
		}

		if peer.closeCalls != 1 || len(peer.requests) != 1 {
			t.Errorf("Close or queued I/O repeated: closes=%d APDUs=%d", peer.closeCalls, len(peer.requests))
		}
	})
}

func TestQueuedCancellationDoesNotChangeSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer := newChannelPeer(t)
		secure := openPeer(t, peer, iso7816.EncodingShort)
		started, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		peer.beforeRecord = func(context.Context) error {
			close(started)
			<-proceed

			return nil
		}
		active := make(chan error, 1)

		go func() { _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0xcb}); active <- err }()

		receiveChannel(t, started, "active exchange did not start")

		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()

		queued := make(chan error, 1)

		go func() { _, err := secure.Exchange(ctx, iso7816.Command{INS: 0x20}); queued <- err }()

		synctest.Wait()

		if err := receiveChannel(t, queued, "queued exchange ignored its deadline"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued Exchange = %v", err)
		}

		if peer.counter != 1 || peer.closeCalls != 0 || len(peer.requests) != 1 {
			t.Fatalf("queued cancellation changed session: counter=%d closes=%d APDUs=%d", peer.counter, peer.closeCalls, len(peer.requests))
		}

		release()

		if err := receiveChannel(t, active, "active exchange did not finish"); err != nil {
			t.Fatal(err)
		}

		peer.beforeRecord = nil
		if _, err := secure.Exchange(t.Context(), iso7816.Command{INS: 0x20}); err != nil || peer.counter != 3 {
			t.Fatalf("reuse after queued cancellation = %v, counter=%d", err, peer.counter)
		}
	})
}

func TestInvalidCommandDoesNotCloseOrTransmit(t *testing.T) {
	peer := newChannelPeer(t)
	secure := openPeer(t, peer, iso7816.EncodingShort)

	for _, command := range []iso7816.Command{{INS: 0xa4}, {INS: 0xc0}, {CLA: 0x10, INS: 0xcb}} {
		if _, err := secure.Exchange(t.Context(), command); !errors.Is(err, iso7816.ErrInvalidCommand) || peer.closeCalls != 0 || len(peer.requests) != 1 {
			t.Errorf("invalid Exchange = %v, closes=%d requests=%d", err, peer.closeCalls, len(peer.requests))
		}
	}
}

func receiveChannel[T any](t testing.TB, channel <-chan T, failure string) T {
	t.Helper()

	select {
	case value := <-channel:
		return value
	case <-time.After(time.Second):
		t.Fatal(failure)

		var zero T

		return zero
	}
}
