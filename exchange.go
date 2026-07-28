package iso7816

import (
	"context"
	"fmt"
	"slices"
)

const defaultMaxResponseSize = maxExtendedResponseDataLength

// Card transmits raw command APDUs and returns raw response APDUs, including
// SW1 and SW2.
type Card interface {
	Transmit(ctx context.Context, apdu []byte) ([]byte, error)
}

// Transmit sends one command APDU and parses one response APDU. It does not
// interpret the status word or issue GET RESPONSE.
func Transmit(ctx context.Context, card Card, command Command) (Response, error) {
	if card == nil {
		return Response{}, ErrNilCard
	}

	apdu, err := command.MarshalBinary()
	if err != nil {
		return Response{}, err
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}

	raw, err := card.Transmit(ctx, apdu)
	if err != nil {
		return Response{}, err
	}

	return ParseResponse(raw)
}

type exchangeOptions struct {
	maxResponseSize int
	moreDataSW1     []byte
}

func newExchangeOptions(opts ...ExchangeOption) exchangeOptions {
	options := exchangeOptions{
		maxResponseSize: defaultMaxResponseSize,
		moreDataSW1:     []byte{0x61},
	}
	for _, option := range opts {
		option(&options)
	}
	return options
}

// ExchangeOption configures response collection for Exchange.
type ExchangeOption func(*exchangeOptions)

// WithMaxResponseSize limits the combined response data size. The default is
// 65536 bytes.
func WithMaxResponseSize(size int) ExchangeOption {
	return func(options *exchangeOptions) {
		options.maxResponseSize = size
	}
}

// WithMoreDataStatusBytes sets the SW1 values which cause Exchange to issue
// GET RESPONSE. ISO 7816 defines 0x61; some cards use 0x9f.
func WithMoreDataStatusBytes(sw1 ...byte) ExchangeOption {
	return func(options *exchangeOptions) {
		options.moreDataSW1 = slices.Clone(sw1)
	}
}

// Exchange sends a command and collects response data through ISO 7816 GET
// RESPONSE commands. It returns the final status without interpreting it.
func Exchange(
	ctx context.Context,
	card Card,
	command Command,
	opts ...ExchangeOption,
) (Response, error) {
	options := newExchangeOptions(opts...)
	if options.maxResponseSize < 0 {
		return Response{}, fmt.Errorf(
			"%w: maximum response size %d",
			ErrInvalidOption,
			options.maxResponseSize,
		)
	}
	if len(options.moreDataSW1) == 0 {
		return Response{}, fmt.Errorf("%w: empty more-data status list", ErrInvalidOption)
	}
	for _, sw1 := range options.moreDataSW1 {
		if sw1 != 0x61 && sw1 != 0x9f {
			return Response{}, fmt.Errorf(
				"%w: unsupported more-data SW1 0x%02x",
				ErrInvalidOption,
				sw1,
			)
		}
	}

	response, err := Transmit(ctx, card, command)
	if err != nil {
		return Response{}, err
	}
	if len(response.Data) > options.maxResponseSize {
		return Response{}, ErrResponseTooLarge
	}

	data := response.Data
	for slices.Contains(options.moreDataSW1, response.Status.SW1()) {
		length, ok := response.Status.MoreDataLength()
		if !ok {
			return Response{}, fmt.Errorf(
				"%w: SW=%s does not encode a response length",
				ErrInvalidResponse,
				response.Status,
			)
		}
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}

		response, err = Transmit(ctx, card, Command{
			CLA:      command.CLA &^ CommandChainingBit,
			INS:      0xc0,
			Le:       length,
			Encoding: EncodingShort,
		})
		if err != nil {
			return Response{}, err
		}
		if len(data) > options.maxResponseSize-len(response.Data) {
			return Response{}, ErrResponseTooLarge
		}
		data = append(data, response.Data...)
	}

	response.Data = data
	return response, nil
}
