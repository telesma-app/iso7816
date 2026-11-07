// Package bertlv encodes and parses definite-length BER-TLV objects.
package bertlv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// ErrInvalidEncoding reports malformed or unsupported BER-TLV data.
var ErrInvalidEncoding = errors.New("bertlv: invalid encoding")

// Append appends a definite-length BER object. The tag is its wire encoding,
// for example 0x7f49, rather than its ASN.1 tag number.
func Append(dst []byte, tag uint32, value []byte) []byte {
	if tag > 0xffffff {
		dst = append(dst, byte(tag>>24))
	}

	if tag > 0xffff {
		dst = append(dst, byte(tag>>16))
	}

	if tag > 0xff {
		dst = append(dst, byte(tag>>8))
	}

	dst = append(dst, byte(tag))

	if len(value) < 0x80 {
		dst = append(dst, byte(len(value)))
	} else {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		n := (bits.Len(uint(len(value))) + 7) / 8
		dst = append(dst, 0x80|byte(n))
		dst = append(dst, length[len(length)-n:]...)
	}

	return append(dst, value...)
}

// Parse reads one definite-length BER object. Value and rest borrow data.
// Tags are limited to four bytes; indefinite lengths are unsupported.
func Parse(data []byte) (tag uint32, value, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("%w: truncated TLV", ErrInvalidEncoding)
	}

	tag = uint32(data[0])
	position := 1

	if data[0]&0x1f == 0x1f {
		for {
			if position >= len(data) || position == 4 {
				return 0, nil, nil, fmt.Errorf("%w: truncated or oversized TLV tag", ErrInvalidEncoding)
			}

			b := data[position]
			if position == 1 && b&0x7f == 0 {
				return 0, nil, nil, fmt.Errorf("%w: invalid TLV tag", ErrInvalidEncoding)
			}

			tag = tag<<8 | uint32(b)
			position++

			if b&0x80 == 0 {
				break
			}
		}
	}

	if position == len(data) {
		return 0, nil, nil, fmt.Errorf("%w: missing TLV length", ErrInvalidEncoding)
	}

	length := uint64(data[position])
	position++

	if length&0x80 != 0 {
		n := int(length & 0x7f)
		if n == 0 || n > 8 || n > len(data)-position {
			return 0, nil, nil, fmt.Errorf("%w: invalid TLV length", ErrInvalidEncoding)
		}

		length = 0
		for _, b := range data[position : position+n] {
			length = length<<8 | uint64(b)
		}

		position += n
	}

	if length > uint64(len(data)-position) {
		return 0, nil, nil, fmt.Errorf("%w: truncated TLV value", ErrInvalidEncoding)
	}

	end := position + int(length)

	return tag, data[position:end:end], data[end:], nil
}
