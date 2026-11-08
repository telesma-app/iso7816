# telesma-app/iso7816

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/iso7816.svg)](https://pkg.go.dev/github.com/telesma-app/iso7816)
[![Go](https://github.com/telesma-app/iso7816/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/iso7816/actions/workflows/go.yml)

`telesma-app/iso7816` is a transport-independent Go library for ISO/IEC 7816-4
command and response APDUs.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

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

Encode a SELECT command and parse a sample response without opening a card:

```go
package main

import (
	"fmt"
	"log"

	"github.com/telesma-app/iso7816"
)

func main() {
	command := iso7816.Command{
		INS:  0xa4,
		P1:   0x04,
		Data: []byte{0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01},
		Le:   256,
	}
	encoded, err := command.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	response, err := iso7816.ParseResponse([]byte{0x01, 0x02, 0x90, 0x00})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("command=%x data=%x status=%s\n", encoded, response.Data, response.Status)
}
```

The command's AID selects FIDO. Application identifiers and response data are
supplied by the caller; encoding an APDU does not send it.

## APDU exchanges

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

The optional `scp11` package provides the P-256/AES-128 GlobalPlatform SCP11b
profile. It requires a compatible card application, a complete APDU transport
and an independently trusted card key.

The [SCP11b guide](docs/scp11.md) covers connection setup, certificate retrieval,
transport requirements, ownership and invalidation. The profile is distinct from
NIST PIV secure messaging; SCP11a and SCP11c are not implemented.

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

## Development

```sh
GOWORK=off go test ./...
```

The test suite uses in-memory cards and does not require hardware.

## License

[Apache License 2.0](LICENSE).
