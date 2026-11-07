package iso7816

import (
	"errors"
	"fmt"
)

var (
	ErrNilCard             = errors.New("iso7816: nil card")
	ErrInvalidCommand      = errors.New("iso7816: invalid command APDU")
	ErrInvalidResponse     = errors.New("iso7816: invalid response APDU")
	ErrInvalidOption       = errors.New("iso7816: invalid option")
	ErrInvalidFragmentSize = errors.New("iso7816: invalid command fragment size")
	ErrResponseTooLarge    = errors.New("iso7816: response data is too large")
)

// APDUError reports a non-success ISO 7816 status word. Applications may use
// SW1 and SW2 to map the status to protocol-specific errors.
type APDUError struct {
	SW1 byte
	SW2 byte
}

func (e *APDUError) Error() string {
	return fmt.Sprintf("iso7816: APDU failed (SW=%02x%02x)", e.SW1, e.SW2)
}

// StatusWord returns SW1 and SW2 as one 16-bit value.
func (e *APDUError) StatusWord() StatusWord {
	return NewStatusWord(e.SW1, e.SW2)
}

// DeviceInvalidatedError marks a connection that must not be reused. Owned
// transports close it before returning; borrowed-card callers must close it.
// It preserves the underlying cause, including an interrupted APDU exchange.
type DeviceInvalidatedError struct {
	Err error
}

func (e *DeviceInvalidatedError) Error() string {
	return e.Err.Error()
}

func (e *DeviceInvalidatedError) Unwrap() error {
	return e.Err
}
