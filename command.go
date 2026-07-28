package iso7816

import (
	"encoding"
	"fmt"
	"slices"
)

const (
	maxShortCommandDataLength     = 0xff
	maxExtendedCommandDataLength  = 0xffff
	maxShortResponseDataLength    = 0x100
	maxExtendedResponseDataLength = 0x10000
)

// Encoding controls the length encoding used by a command APDU.
type Encoding uint8

const (
	// EncodingAuto selects short encoding when the command fits and extended
	// encoding otherwise.
	EncodingAuto Encoding = iota
	EncodingShort
	EncodingExtended
)

// Command is an ISO 7816 command APDU. Le is the maximum expected response
// data length: zero omits Le, 256 encodes as zero in a short APDU, and 65536
// encodes as two zero bytes in an extended APDU.
type Command struct {
	CLA      byte
	INS      byte
	P1       byte
	P2       byte
	Data     []byte
	Le       uint32
	Encoding Encoding
}

var _ encoding.BinaryMarshaler = Command{}

// MarshalBinary encodes c as an ISO 7816 command APDU.
func (c Command) MarshalBinary() ([]byte, error) {
	encoding, err := c.effectiveEncoding()
	if err != nil {
		return nil, err
	}

	header := []byte{c.CLA, c.INS, c.P1, c.P2}
	if len(c.Data) == 0 && c.Le == 0 {
		return header, nil
	}

	switch encoding {
	case EncodingShort:
		return c.marshalShort(header), nil
	case EncodingExtended:
		return c.marshalExtended(header), nil
	default:
		panic("unreachable ISO 7816 command encoding")
	}
}

func (c Command) effectiveEncoding() (Encoding, error) {
	if len(c.Data) > maxExtendedCommandDataLength {
		return 0, fmt.Errorf(
			"%w: data length %d exceeds %d",
			ErrInvalidCommand,
			len(c.Data),
			maxExtendedCommandDataLength,
		)
	}
	if c.Le > maxExtendedResponseDataLength {
		return 0, fmt.Errorf(
			"%w: Le %d exceeds %d",
			ErrInvalidCommand,
			c.Le,
			maxExtendedResponseDataLength,
		)
	}

	switch c.Encoding {
	case EncodingAuto:
		if len(c.Data) <= maxShortCommandDataLength && c.Le <= maxShortResponseDataLength {
			return EncodingShort, nil
		}
		return EncodingExtended, nil
	case EncodingShort:
		if len(c.Data) > maxShortCommandDataLength {
			return 0, fmt.Errorf(
				"%w: data length %d exceeds short APDU limit %d",
				ErrInvalidCommand,
				len(c.Data),
				maxShortCommandDataLength,
			)
		}
		if c.Le > maxShortResponseDataLength {
			return 0, fmt.Errorf(
				"%w: Le %d exceeds short APDU limit %d",
				ErrInvalidCommand,
				c.Le,
				maxShortResponseDataLength,
			)
		}
		return EncodingShort, nil
	case EncodingExtended:
		return EncodingExtended, nil
	default:
		return 0, fmt.Errorf("%w: unknown encoding %d", ErrInvalidCommand, c.Encoding)
	}
}

func (c Command) marshalShort(header []byte) []byte {
	switch {
	case len(c.Data) == 0:
		return append(header, shortLength(c.Le))
	case c.Le == 0:
		return slices.Concat(header, []byte{byte(len(c.Data))}, c.Data)
	default:
		return slices.Concat(
			header,
			[]byte{byte(len(c.Data))},
			c.Data,
			[]byte{shortLength(c.Le)},
		)
	}
}

func (c Command) marshalExtended(header []byte) []byte {
	switch {
	case len(c.Data) == 0:
		le1, le2 := extendedLength(c.Le)
		return append(header, 0x00, le1, le2)
	case c.Le == 0:
		lc1, lc2 := extendedLength(uint32(len(c.Data)))
		return slices.Concat(header, []byte{0x00, lc1, lc2}, c.Data)
	default:
		lc1, lc2 := extendedLength(uint32(len(c.Data)))
		le1, le2 := extendedLength(c.Le)
		return slices.Concat(
			header,
			[]byte{0x00, lc1, lc2},
			c.Data,
			[]byte{le1, le2},
		)
	}
}

func shortLength(length uint32) byte {
	return byte(length % maxShortResponseDataLength)
}

func extendedLength(length uint32) (byte, byte) {
	length %= maxExtendedResponseDataLength
	return byte(length >> 8), byte(length)
}
