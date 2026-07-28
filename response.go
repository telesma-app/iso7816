package iso7816

import (
	"encoding"
	"fmt"
	"slices"
)

// StatusWord contains the SW1 and SW2 bytes returned by a smart card.
type StatusWord uint16

const (
	StatusSuccess StatusWord = 0x9000
)

// NewStatusWord combines SW1 and SW2.
func NewStatusWord(sw1, sw2 byte) StatusWord {
	return StatusWord(uint16(sw1)<<8 | uint16(sw2))
}

// SW1 returns the most significant status byte.
func (s StatusWord) SW1() byte {
	return byte(s >> 8)
}

// SW2 returns the least significant status byte.
func (s StatusWord) SW2() byte {
	return byte(s)
}

// String returns the four hexadecimal status-word digits.
func (s StatusWord) String() string {
	return fmt.Sprintf("%04x", uint16(s))
}

// IsSuccess reports whether the status word is 0x9000.
func (s StatusWord) IsSuccess() bool {
	return s == StatusSuccess
}

// MoreDataLength returns the response length indicated by a 0x61xx or 0x9fxx
// status. An SW2 value of zero means 256 bytes.
func (s StatusWord) MoreDataLength() (uint32, bool) {
	if s.SW1() != 0x61 && s.SW1() != 0x9f {
		return 0, false
	}
	if s.SW2() == 0 {
		return maxShortResponseDataLength, true
	}
	return uint32(s.SW2()), true
}

// CorrectLength returns the response length indicated by a 0x6cxx status. An
// SW2 value of zero means 256 bytes. The package does not retry automatically
// because application commands may have side effects.
func (s StatusWord) CorrectLength() (uint32, bool) {
	if s.SW1() != 0x6c {
		return 0, false
	}
	if s.SW2() == 0 {
		return maxShortResponseDataLength, true
	}
	return uint32(s.SW2()), true
}

// Response is an ISO 7816 response APDU.
type Response struct {
	Data   []byte
	Status StatusWord
}

var _ encoding.BinaryMarshaler = Response{}

// ParseResponse parses response data followed by SW1 and SW2. The returned
// response owns a copy of the data.
func ParseResponse(raw []byte) (Response, error) {
	if len(raw) < 2 {
		return Response{}, ErrInvalidResponse
	}

	return Response{
		Data:   slices.Clone(raw[:len(raw)-2]),
		Status: NewStatusWord(raw[len(raw)-2], raw[len(raw)-1]),
	}, nil
}

// MarshalBinary encodes response data followed by SW1 and SW2.
func (r Response) MarshalBinary() ([]byte, error) {
	return slices.Concat(r.Data, []byte{r.Status.SW1(), r.Status.SW2()}), nil
}

// APDUError returns nil for a successful status word and a typed error for
// every other final status.
func (r Response) APDUError() error {
	if r.Status.IsSuccess() {
		return nil
	}

	return &APDUError{SW1: r.Status.SW1(), SW2: r.Status.SW2()}
}
