# go-ctap/iso7816

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/iso7816.svg)](https://pkg.go.dev/github.com/telesma-app/iso7816)
[![Go](https://github.com/telesma-app/iso7816/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/iso7816/actions/workflows/go.yml)

`go-ctap/iso7816` is a transport-independent Go library for ISO/IEC 7816-4
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

The package has no platform-specific code and no runtime dependencies.

## Installation

```sh
go get github.com/telesma-app/iso7816@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

`Card` is the contextual raw-APDU interface implemented by
[`go-ctap/pcsc`](https://github.com/telesma-app/pcsc):

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
for _, command := range commands {
    response, err := iso7816.Transmit(ctx, card, command)
    // Check every intermediate response before sending the next fragment.
}
```

Application protocols may need to modify fields on individual fragments.
`Chain` only applies ISO 7816 framing rules and does not transmit them
automatically.

## Cancellation and concurrency

Context cancellation is passed to the underlying `Card`. A canceled APDU is
not retried: the card or reader may already have processed it.

`Exchange` performs several APDUs when it receives a chained response. The
caller must prevent another application or goroutine from interleaving APDUs,
for example by using an exclusive PC/SC connection or transaction.

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

## Scope

This package does not provide:

- PC/SC reader discovery, events, or connection management;
- application identifiers or application commands;
- CTAP, PIV, OpenPGP, or GlobalPlatform semantics;
- BER-TLV data models;
- secure messaging, PIN workflows, or key management.

Use [`go-ctap/pcsc`](https://github.com/telesma-app/pcsc) for PC/SC access and
[`go-ctap/ctap`](https://github.com/telesma-app/ctap) for FIDO2 commands.

## Testing

```sh
go test ./...
```

The test suite uses in-memory cards and does not require hardware.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
