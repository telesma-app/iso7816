package scp11

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/iso7816/internal/bertlv"
	channelcrypto "github.com/telesma-app/iso7816/internal/scp11"
)

// ErrAuthentication means the card's receipt did not authenticate its key
// agreement using the caller's trusted static key.
var ErrAuthentication = errors.New("scp11: receipt authentication failed")

// Parameters selects the SCP11b static key and APDU format. PeerKey must be a
// trusted P-256 key, for example from a certificate whose chain and intended use
// the caller has verified independently of the connection. A card-supplied key
// is not trusted merely because ReadCertificates returned it.
//
// Encoding must explicitly select EncodingShort (with command chaining) or
// EncodingExtended. There is no automatic fallback.
type Parameters struct {
	KeyID      byte
	KeyVersion byte
	PeerKey    *ecdh.PublicKey
	Encoding   iso7816.Encoding
}

// APDU exchanges complete logical commands and responses. It fragments a
// protected command only after encryption, using short-APDU command chaining
// when needed, and assembles the complete response before returning it for
// authentication. Framing GET RESPONSE is unprotected with CLA 00. The final
// status word is returned without interpretation. Cancellation before I/O returns
// a plain context error and leaves the connection usable; an interrupted
// exchange after I/O must return iso7816.DeviceInvalidatedError.
type APDU interface {
	Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error)
}

// Device is an owned APDU connection. Close must be safe alongside Exchange.
type Device interface {
	APDU
	io.Closer
}

// Transport owns an authenticated SCP11b connection. Create it with Open.
// It must not be copied or used alongside independent users of its connection.
type Transport struct {
	connection Device
	session    *channelcrypto.Session
	mu         chan struct{}
	cryptoMu   sync.Mutex
	closed     chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

var _ Device = (*Transport)(nil)

// Open establishes SCP11b over the selected application using a fresh host
// ephemeral key. It does not select or switch applications.
// It borrows connection during the handshake and takes ownership on success.
// On failure the caller retains ownership; iso7816.DeviceInvalidatedError means the
// connection was closed and must not be reused. The caller serializes the
// handshake with all other connection operations.
func Open(ctx context.Context, connection Device, parameters Parameters) (*Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if parameters.Encoding != iso7816.EncodingShort && parameters.Encoding != iso7816.EncodingExtended {
		return nil, fmt.Errorf("scp11: select short or extended APDU encoding explicitly")
	}

	if parameters.PeerKey.Curve() != ecdh.P256() {
		return nil, fmt.Errorf("scp11: only P-256 card keys are supported")
	}

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	command := internalAuthenticateCommand(parameters.KeyVersion, parameters.KeyID, ephemeral.PublicKey().Bytes())

	response, err := connection.Exchange(ctx, command)
	if err != nil {
		return nil, err
	}

	if err := response.APDUError(); err != nil {
		return nil, fmt.Errorf("scp11: INTERNAL AUTHENTICATE: %w", err)
	}

	point, receipt, err := parseInternalAuthenticateResponse(response.Data)
	if err != nil {
		return nil, errors.Join(&iso7816.DeviceInvalidatedError{Err: err}, connection.Close())
	}

	cardEphemeral, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, errors.Join(&iso7816.DeviceInvalidatedError{Err: err}, connection.Close())
	}

	ephemeralZ, err := ephemeral.ECDH(cardEphemeral)
	if err != nil {
		return nil, errors.Join(&iso7816.DeviceInvalidatedError{Err: err}, connection.Close())
	}
	defer clear(ephemeralZ)

	staticZ, err := ephemeral.ECDH(parameters.PeerKey)
	if err != nil {
		return nil, errors.Join(&iso7816.DeviceInvalidatedError{Err: err}, connection.Close())
	}
	defer clear(staticZ)

	receiptKey, keys := channelcrypto.DeriveKeys(ephemeralZ, staticZ)
	defer clear(receiptKey)

	// The receipt authenticates the original encoded card-key TLV, not a
	// normalized re-encoding. parseInternalAuthenticateResponse validated it.
	_, _, rest, _ := bertlv.Parse(response.Data)
	transcript := append(command.Data, response.Data[:len(response.Data)-len(rest)]...)

	expected := channelcrypto.CMAC(receiptKey, transcript)
	if subtle.ConstantTimeCompare(expected[:], receipt[:]) != 1 {
		keys.Clear()
		return nil, errors.Join(&iso7816.DeviceInvalidatedError{Err: ErrAuthentication}, connection.Close())
	}

	return &Transport{
		connection: connection,
		session:    channelcrypto.NewSession(keys, receipt, parameters.Encoding),
		mu:         make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}, nil
}

// Exchange protects one whole logical command before fragmentation and checks
// the complete response before returning plaintext. Authenticated error status
// words remain uninterpreted. SELECT and manual GET RESPONSE are unsupported;
// framing GET RESPONSE commands belong to the underlying transport.
func (t *Transport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := t.lock(ctx); err != nil {
		return iso7816.Response{}, err
	}
	defer func() { <-t.mu }()

	t.cryptoMu.Lock()
	select {
	case <-t.closed:
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	default:
	}

	protected, next, err := t.session.Protect(command)
	t.cryptoMu.Unlock()

	if err != nil {
		return iso7816.Response{}, err
	}

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	response, err := t.connection.Exchange(ctx, protected)
	if err != nil {
		var invalidated *iso7816.DeviceInvalidatedError
		if !errors.As(err, &invalidated) && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			// The underlying complete-exchange contract marks cancellation
			// after I/O as invalidation. Before I/O, Protect changed no state.
			return iso7816.Response{}, err
		}

		return iso7816.Response{}, t.invalidate(err)
	}

	t.cryptoMu.Lock()
	select {
	case <-t.closed:
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	default:
	}

	plaintext, err := t.session.Unprotect(response, next)
	t.cryptoMu.Unlock()

	if err != nil {
		return iso7816.Response{}, t.invalidate(err)
	}

	return plaintext, nil
}

func (t *Transport) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return io.ErrClosedPipe
	case t.mu <- struct{}{}:
	}

	if err := ctx.Err(); err != nil {
		<-t.mu
		return err
	}

	select {
	case <-t.closed:
		<-t.mu
		return io.ErrClosedPipe
	default:
	}

	return nil
}

func (t *Transport) invalidate(err error) error {
	var invalidated *iso7816.DeviceInvalidatedError
	if !errors.As(err, &invalidated) {
		err = &iso7816.DeviceInvalidatedError{Err: err}
	}

	return errors.Join(err, t.Close())
}

// Close prevents further operations, closes the connection once, and clears
// owned session key material. It does not acquire the exchange gate. Crypto
// cleanup is serialized with encryption/decryption, never with blocking I/O.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.closeErr = t.connection.Close()
		t.cryptoMu.Lock()
		t.session.Clear()
		t.cryptoMu.Unlock()
	})

	return t.closeErr
}
