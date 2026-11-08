# SCP11b secure channels

[Back to the overview](../README.md).

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
