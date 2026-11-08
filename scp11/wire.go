package scp11

import (
	"crypto/ecdh"
	"fmt"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
)

// internalAuthenticateCommand constructs GlobalPlatform SCP11b INTERNAL
// AUTHENTICATE for AES-128 session keys with command and response encryption
// and MACs. hostPoint is the host's uncompressed P-256 ephemeral public key.
func internalAuthenticateCommand(keyVersion, keyID byte, hostPoint []byte) iso7816.Command {
	data := []byte{
		0xa6, 0x0d,
		0x90, 0x02, 0x11, 0x00,
		0x95, 0x01, 0x3c,
		0x80, 0x01, 0x88,
		0x81, 0x01, 0x10,
	}

	return iso7816.Command{
		CLA: 0x80, INS: 0x88, P1: keyVersion, P2: keyID,
		Data: bertlv.Append(data, 0x5f49, hostPoint),
		Le:   256, Encoding: iso7816.EncodingShort,
	}
}

// parseInternalAuthenticateResponse parses the ordered ephemeral P-256 public
// key (5F49) and 16-byte receipt (86) returned by INTERNAL AUTHENTICATE. point
// borrows data; receipt is returned by value. This validates encoding, not
// receipt authenticity.
func parseInternalAuthenticateResponse(data []byte) (point []byte, receipt [16]byte, err error) {
	tag, point, rest, err := bertlv.Parse(data)
	if err != nil {
		return nil, receipt, fmt.Errorf("%w: SCP11b public key: %v", iso7816.ErrInvalidResponse, err)
	}

	if tag != 0x5f49 {
		return nil, receipt, fmt.Errorf("%w: expected SCP11b public key", iso7816.ErrInvalidResponse)
	}

	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, receipt, fmt.Errorf("%w: SCP11b public key: %v", iso7816.ErrInvalidResponse, err)
	}

	tag, value, rest, err := bertlv.Parse(rest)
	if err != nil {
		return nil, receipt, fmt.Errorf("%w: SCP11b receipt: %v", iso7816.ErrInvalidResponse, err)
	}

	if tag != 0x86 || len(value) != len(receipt) || len(rest) != 0 {
		return nil, receipt, fmt.Errorf("%w: expected single SCP11b receipt", iso7816.ErrInvalidResponse)
	}

	copy(receipt[:], value)

	return point, receipt, nil
}
