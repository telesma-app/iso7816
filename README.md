# telesma-app/iso7816

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/iso7816.svg)](https://pkg.go.dev/github.com/telesma-app/iso7816)
[![Go](https://github.com/telesma-app/iso7816/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/iso7816/actions/workflows/go.yml)

`telesma-app/iso7816` is a transport-independent Go library for ISO/IEC 7816-4
command and response APDUs.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Support

The package supports:

- command APDU cases 1 through 4;
- automatic, short and extended length encoding;
- response APDU and status-word parsing;
- ISO 7816 `GET RESPONSE`, including the commonly used `0x9fxx` variant;
- command chaining;
- response and command size validation;
- contextual raw-card connections such as `pcsc.Card`.

The root package has no platform-specific code and no runtime dependencies.

The optional `scp11` subpackage establishes GlobalPlatform SCP11b channels
over complete APDU transports. It uses P-256 key agreement, AES-128 encryption,
and command and response MACs. It is independent of PC/SC and the selected
smart-card application. See [SCP11b](#scp11b-secure-channels) for its transport
and ownership contracts. The subpackage uses `github.com/telesma-app/bertlv`
for BER-TLV encoding and parsing.

## Installation

```sh
go get github.com/telesma-app/iso7816@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

`Card` is the contextual raw-APDU interface implemented by
[`telesma-app/pcsc`](https://github.com/telesma-app/pcsc):

```go
type Card interface {
    Transmit(context.Context, []byte) ([]byte, error)
}
```

This example selects an application and collects a potentially chained
response:

```go
response, err := iso7816.Exchange(ctx, card, iso7816.Command{
    CLA:  0x00,
    INS:  0xa4,
    P1:   0x04,
    P2:   0x00,
    Data: aid,
    Le:   256,
}, iso7816.WithMoreDataStatusBytes(0x61, 0x9f))
if err != nil {
    log.Fatal(err)
}
if err := response.APDUError(); err != nil {
    log.Fatal(err)
}
fmt.Printf("application response: %x\n", response.Data)
```

`Exchange` follows `0x61xx` with `GET RESPONSE` by default. It returns the
final status word without interpreting application-specific meanings.
`Transmit` sends exactly one command when automatic response collection is
not wanted.

## APDU encoding

`Le` uses the decoded expected length. Zero omits the field, 256 becomes a
zero byte in a short APDU, and 65536 becomes two zero bytes in an extended
APDU:

```go
apdu, err := (iso7816.Command{
    CLA:      0x80,
    INS:      0xda,
    P1:       0x01,
    Data:     payload,
    Le:       65536,
    Encoding: iso7816.EncodingExtended,
}).MarshalBinary()
```

`EncodingAuto`, the zero value, uses short encoding whenever the command fits.

Responses contain copied data and a `StatusWord`:

```go
response, err := iso7816.ParseResponse(raw)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("data=%x SW=%s\n", response.Data, response.Status)
```

## Command chaining

`Chain` creates command fragments and sets the command-chaining CLA bit on
every non-final fragment:

```go
commands, err := iso7816.Chain(command, 240)
if err != nil {
    log.Fatal(err)
}
response, err := iso7816.ExchangeChain(ctx, card, commands)
if err != nil {
    log.Fatal(err)
}
if err := response.APDUError(); err != nil {
    log.Fatal(err)
}
```

Application protocols may need to modify fields on individual fragments.
`Chain` only applies ISO 7816 framing rules. Pass its nonempty result to
`ExchangeChain` after any application-specific fragment changes.

`ExchangeChain` requires every intermediate response to contain no data and
status `0x9000`. Any intermediate rejection returns `*APDUError` and stops the
chain; `0x61xx`, `0x9fxx`, and application-specific statuses do not trigger
polling at this stage. The last command uses the same response collection and
options as `Exchange`, returning its final status without interpreting it.

## Cancellation and concurrency

Context cancellation is passed to the underlying `Card`. A canceled APDU is
not retried: the card or reader may already have processed it.

`Exchange` and `ExchangeChain` can perform several APDUs. The caller must prevent
another application or goroutine from interleaving APDUs, for example by using
an exclusive PC/SC connection or transaction. Both functions borrow the card;
the caller manages its lifetime and decides whether an interrupted exchange
requires a reset or a new connection.

## Errors

Malformed commands and responses support `errors.Is` with package errors such
as `ErrInvalidCommand` and `ErrInvalidResponse`. Size limits return
`ErrResponseTooLarge` or `ErrInvalidFragmentSize`.

`Response.APDUError` converts a non-success final status into `*APDUError`
while retaining SW1 and SW2:

```go
var apduErr *iso7816.APDUError
if errors.As(err, &apduErr) {
    log.Printf("card returned SW=%04x", apduErr.StatusWord())
}
```

Underlying card errors are returned unchanged.

## SCP11b secure channels

`github.com/telesma-app/iso7816/scp11` implements the P-256/AES-128 GlobalPlatform
SCP11b profile. It does not implement SCP11a, SCP11c, other cryptographic profiles,
or the distinct NIST SP 800-73 PIV secure messaging suites `27`/`2E`. The selected
card application must support this profile.

Select the intended application before opening a channel. Supply a previously
trusted static P-256 card key and explicit key reference and APDU encoding:

```go
channel, err := scp11.Open(ctx, connection, scp11.Parameters{
    KeyID:      keyID,
    KeyVersion: keyVersion,
    PeerKey:    trustedPeerKey,
    Encoding:   iso7816.EncodingExtended,
})
if err != nil {
    return errors.Join(err, connection.Close())
}
defer channel.Close()

response, err := channel.Exchange(ctx, command)
```

`connection` implements `scp11.Device`: complete logical `Exchange` operations
and `Close`, which must be safe during an exchange. The transport fragments a
protected command only after encryption and authentication, collects the full
response before authentication, and issues framing `GET RESPONSE` with CLA `00`.
It must distinguish cancellation before I/O from an interrupted exchange:
interruption after I/O starts returns `iso7816.DeviceInvalidatedError`. A direct
wrapper around the root package's `Exchange` alone does not supply these
framing and invalidation contracts. The PIV library's `transport/iso7816`
implements them.

`scp11.Open` performs no application selection. It authenticates the card's
key-agreement receipt and takes ownership of the connection on success. The
caller retains ownership on failure; a malformed successful handshake or
invalid receipt additionally invalidates and closes the connection. Stop using
the underlying connection independently after a successful open.

`scp11.ReadCertificates` borrows a complete APDU transport, selects the
GlobalPlatform Security Domain, and returns an **untrusted**, leaf-last X.509
certificate chain. Validate its trust, intended use, and device identity with
previously trusted material before passing the card key to `Open`. Reselect the
intended application after retrieval. Certificate retrieval does not implement
trust on first use or perform implicit PKI policy.

The channel serializes protected exchanges. An authenticated APDU rejection
preserves the session. Missing or invalid response authentication and loss of
channel state invalidate and close the connection and clear session keys.
`Close` releases waiting callers without waiting for the active exchange gate.
There is no plaintext fallback, automatic reconnect, or replay. Application
`SELECT` and manual `GET RESPONSE` are unsupported within an established channel.

## Scope

The root package does not provide:

- PC/SC reader discovery, events, or connection management;
- application identifiers or application commands;
- CTAP, PIV, OpenPGP, or GlobalPlatform semantics;
- BER-TLV data models;
- PIN workflows or key management.

Secure messaging is provided only by the separate `scp11` subpackage described
above; the root package remains independent of GlobalPlatform semantics.

Use [`telesma-app/pcsc`](https://github.com/telesma-app/pcsc) for PC/SC access and
[`telesma-app/ctap`](https://github.com/telesma-app/ctap) for FIDO2 commands.

## Testing

```sh
go test ./...
```

The test suite uses in-memory cards and does not require hardware.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
