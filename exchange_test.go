package iso7816

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type exchange struct {
	command  []byte
	response []byte
	err      error
	after    func()
}

type fakeCard struct {
	t         *testing.T
	exchanges []exchange
}

func (c *fakeCard) Transmit(ctx context.Context, command []byte) ([]byte, error) {
	c.t.Helper()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(c.exchanges) == 0 {
		c.t.Fatalf("unexpected command: %x", command)
	}

	next := c.exchanges[0]
	c.exchanges = c.exchanges[1:]
	if !bytes.Equal(command, next.command) {
		c.t.Errorf("command = %x, want %x", command, next.command)
	}
	if next.after != nil {
		next.after()
	}
	return bytes.Clone(next.response), next.err
}

func TestTransmitEncodesCommandAndParsesResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		command:  []byte{0x00, 0x84, 0x00, 0x00, 0x08},
		response: []byte{0x01, 0x02, 0x90, 0x00},
	}}}

	response, err := Transmit(t.Context(), card, Command{INS: 0x84, Le: 8})

	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !bytes.Equal(response.Data, []byte{0x01, 0x02}) || response.Status != StatusSuccess {
		t.Errorf("response = %#v", response)
	}
	if len(card.exchanges) != 0 {
		t.Errorf("%d exchanges remain", len(card.exchanges))
	}
}

func TestExchangeCollectsResponseChaining(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{
			command:  []byte{0x80, 0xca, 0x00, 0x00, 0x00},
			response: []byte{0x01, 0x61, 0x02},
		},
		{
			command:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
			response: []byte{0x02, 0x03, 0x61, 0x00},
		},
		{
			command:  []byte{0x80, 0xc0, 0x00, 0x00, 0x00},
			response: []byte{0x04, 0x90, 0x00},
		},
	}}

	response, err := Exchange(t.Context(), card, Command{CLA: 0x80, INS: 0xca, Le: 256})

	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(response.Data, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("Data = %x", response.Data)
	}
	if response.Status != StatusSuccess {
		t.Errorf("Status = %s", response.Status)
	}
}

func TestExchangeSupportsConfiguredLegacyStatus(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{
			command:  []byte{0x00, 0xa4, 0x04, 0x00, 0x00},
			response: []byte{0x01, 0x9f, 0x01},
		},
		{
			command:  []byte{0x00, 0xc0, 0x00, 0x00, 0x01},
			response: []byte{0x02, 0x90, 0x00},
		},
	}}

	response, err := Exchange(
		t.Context(),
		card,
		Command{INS: 0xa4, P1: 0x04, Le: 256},
		WithMoreDataStatusBytes(0x61, 0x9f),
	)

	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(response.Data, []byte{0x01, 0x02}) {
		t.Errorf("Data = %x", response.Data)
	}
}

func TestExchangeReturnsFinalStatusUninterpreted(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		command:  []byte{0x00, 0xca, 0x00, 0x00},
		response: []byte{0x6a, 0x82},
	}}}

	response, err := Exchange(t.Context(), card, Command{INS: 0xca})

	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if response.Status != 0x6a82 {
		t.Errorf("Status = %s, want 6a82", response.Status)
	}
}

func TestExchangeChecksContextBeforeGetResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	card := &fakeCard{t: t, exchanges: []exchange{{
		command:  []byte{0x00, 0xca, 0x00, 0x00},
		response: []byte{0x61, 0x01},
		after:    cancel,
	}}}

	_, err := Exchange(ctx, card, Command{INS: 0xca})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange error = %v, want context.Canceled", err)
	}
	if len(card.exchanges) != 0 {
		t.Errorf("%d exchanges remain", len(card.exchanges))
	}
}

func TestExchangeRejectsOversizedResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		command:  []byte{0x00, 0xca, 0x00, 0x00},
		response: []byte{0x01, 0x02, 0x90, 0x00},
	}}}

	_, err := Exchange(
		t.Context(),
		card,
		Command{INS: 0xca},
		WithMaxResponseSize(1),
	)

	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Exchange error = %v, want ErrResponseTooLarge", err)
	}
}

func TestExchangeRejectsInvalidOptionsBeforeIO(t *testing.T) {
	tests := []struct {
		name   string
		option ExchangeOption
	}{
		{name: "negative response limit", option: WithMaxResponseSize(-1)},
		{name: "empty status list", option: WithMoreDataStatusBytes()},
		{name: "unsupported status", option: WithMoreDataStatusBytes(0x91)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := &fakeCard{t: t}

			_, err := Exchange(t.Context(), card, Command{}, tt.option)

			if !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("Exchange error = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func TestTransmitValidationAndErrors(t *testing.T) {
	wantErr := errors.New("reader unavailable")
	tests := []struct {
		name    string
		ctx     context.Context
		card    Card
		command Command
		wantErr error
	}{
		{
			name:    "nil card",
			ctx:     t.Context(),
			command: Command{},
			wantErr: ErrNilCard,
		},
		{
			name:    "invalid command",
			ctx:     t.Context(),
			card:    &fakeCard{t: t},
			command: Command{Encoding: Encoding(99)},
			wantErr: ErrInvalidCommand,
		},
		{
			name: "canceled context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			}(),
			card:    &fakeCard{t: t},
			command: Command{},
			wantErr: context.Canceled,
		},
		{
			name: "card error",
			ctx:  t.Context(),
			card: &fakeCard{t: t, exchanges: []exchange{{
				command: []byte{0x00, 0x00, 0x00, 0x00},
				err:     wantErr,
			}}},
			command: Command{},
			wantErr: wantErr,
		},
		{
			name: "malformed response",
			ctx:  t.Context(),
			card: &fakeCard{t: t, exchanges: []exchange{{
				command:  []byte{0x00, 0x00, 0x00, 0x00},
				response: []byte{0x90},
			}}},
			command: Command{},
			wantErr: ErrInvalidResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Transmit(tt.ctx, tt.card, tt.command)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Transmit error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
