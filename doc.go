// Package iso7816 encodes and exchanges ISO/IEC 7816-4 command and response
// APDUs.
//
// The package is independent of the connection backend and smart-card
// application. A Card can be backed by PC/SC, NFC, a secure element, or a test
// double. Application packages such as CTAP, PIV, and OpenPGP define their own
// commands, status semantics, and higher-level workflows on top.
package iso7816
