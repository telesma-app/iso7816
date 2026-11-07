// Package scp11 establishes GlobalPlatform SCP11b channels over complete ISO 7816
// APDU exchanges, independently of the connection backend and card application.
// It implements the P-256 and AES-128 profile used by the Yubico and TOKEN2 PIV
// tools, with encrypted commands and responses and eight-byte command and
// response MACs. The selected card application must support this profile.
// It does not implement SCP11a, SCP11c, other cipher suites, or the NIST SP 800-73
// secure messaging cipher suites 27 and 2E.
//
// The caller selects the intended application before Open and supplies a
// previously trusted static P-256 card key, key reference, and APDU encoding.
// ReadCertificates retrieves an untrusted certificate chain and leaves the
// GlobalPlatform Security Domain selected; retrieval alone does not establish
// trust. Select the intended application again before establishing its channel.
//
// Open authenticates the card's key agreement receipt. Ownership transfers on
// success. On failure the caller retains ownership, but a failed receipt or
// malformed successful handshake invalidates and closes the connection. No
// plaintext downgrade or reconnect is performed.
//
// Transport serializes complete encrypted exchanges. An authenticated APDU
// rejection preserves the channel; missing or invalid response authentication
// and interrupted exchanges invalidate it. Close releases waiting callers and
// closes the underlying connection without waiting for the exchange gate.
// Session keys are cleared with cryptographic operations serialized separately
// from blocking I/O. The underlying connection fragments protected commands and
// collects protected responses before the channel authenticates and decrypts them.
package scp11
