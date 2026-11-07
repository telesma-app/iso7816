package iso7816

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestExchangeChainSingleCommandReturnsFinalStatus(t *testing.T) {
	for _, status := range []StatusWord{0x9000, 0x63c2, 0x9100} {
		t.Run(status.String(), func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{
				command:  []byte{0x00, 0x87, 0x11, 0x9a, 0x02, 0x7c, 0x00, 0x00},
				response: []byte{0x01, status.SW1(), status.SW2()},
			}}}
			commands := []Command{{
				INS: 0x87, P1: 0x11, P2: 0x9a,
				Data: []byte{0x7c, 0x00}, Le: 256, Encoding: EncodingShort,
			}}

			response, err := ExchangeChain(t.Context(), card, commands)

			if err != nil {
				t.Fatal(err)
			}
			if response.Status != status || !bytes.Equal(response.Data, []byte{0x01}) {
				t.Errorf("response = %#v, want data 01 and status %s", response, status)
			}
			if len(card.exchanges) != 0 {
				t.Errorf("%d exchanges remain", len(card.exchanges))
			}
		})
	}
}

func TestExchangeChainRetainsFragmentsAndCollectsFinalResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{
			command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
			response: []byte{0x90, 0x00},
		},
		{
			command:  []byte{0x80, 0xda, 0x81, 0x03, 0x01, 0xcc, 0x00},
			response: []byte{0x01, 0x61, 0x02},
		},
		{
			command:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
			response: []byte{0x02, 0x03, 0x9f, 0x01},
		},
		{
			command:  []byte{0x80, 0xc0, 0x00, 0x00, 0x01},
			response: []byte{0x04, 0x63, 0xc2},
		},
	}}

	response, err := ExchangeChain(t.Context(), card, testCommandChain(), WithMoreDataStatusBytes(0x61, 0x9f))

	if err != nil {
		t.Fatal(err)
	}
	if response.Status != 0x63c2 || !bytes.Equal(response.Data, []byte{1, 2, 3, 4}) {
		t.Errorf("response = %#v, want data 01020304 and status 63c2", response)
	}
	if len(card.exchanges) != 0 {
		t.Errorf("%d exchanges remain", len(card.exchanges))
	}
}

func TestExchangeChainStopsAfterRejectedFragment(t *testing.T) {
	for _, status := range []StatusWord{0x6982, 0x6101, 0x9f01, 0x9100} {
		t.Run(status.String(), func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{
				command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
				response: []byte{status.SW1(), status.SW2()},
			}}}

			_, err := ExchangeChain(t.Context(), card, testCommandChain(), WithMoreDataStatusBytes(0x61, 0x9f))

			var apduErr *APDUError
			if !errors.As(err, &apduErr) || apduErr.StatusWord() != status {
				t.Errorf("error = %v, want APDUError with status %s", err, status)
			}
			if len(card.exchanges) != 0 {
				t.Errorf("%d exchanges remain", len(card.exchanges))
			}
		})
	}
}

func TestExchangeChainRejectsIntermediateData(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
		response: []byte{0x01, 0x90, 0x00},
	}}}

	_, err := ExchangeChain(t.Context(), card, testCommandChain())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("error = %v, want ErrInvalidResponse", err)
	}
}

func TestExchangeChainCancellation(t *testing.T) {
	for _, stage := range []string{"before first command", "between command fragments", "between GET RESPONSE commands"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			card := &fakeCard{t: t}
			switch stage {
			case "before first command":
				cancel()
			case "between command fragments":
				card.exchanges = []exchange{{
					command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
					response: []byte{0x90, 0x00}, after: cancel,
				}}
			case "between GET RESPONSE commands":
				card.exchanges = []exchange{
					{
						command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
						response: []byte{0x90, 0x00},
					},
					{
						command:  []byte{0x80, 0xda, 0x81, 0x03, 0x01, 0xcc, 0x00},
						response: []byte{0x01, 0x61, 0x02},
					},
					{
						command:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
						response: []byte{0x02, 0x61, 0x01}, after: cancel,
					},
				}
			}

			_, err := ExchangeChain(ctx, card, testCommandChain())

			if !errors.Is(err, context.Canceled) {
				t.Errorf("error = %v, want context.Canceled", err)
			}
			if len(card.exchanges) != 0 {
				t.Errorf("%d exchanges remain", len(card.exchanges))
			}
		})
	}
}

func TestExchangeChainPreservesCardErrors(t *testing.T) {
	for _, stage := range []string{"intermediate command", "final command"} {
		t.Run(stage, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{
				command: []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
				err:     io.ErrClosedPipe,
			}}}
			if stage == "final command" {
				card.exchanges[0].err = nil
				card.exchanges[0].response = []byte{0x90, 0x00}
				card.exchanges = append(card.exchanges, exchange{
					command: []byte{0x80, 0xda, 0x81, 0x03, 0x01, 0xcc, 0x00},
					err:     io.ErrClosedPipe,
				})
			}

			_, err := ExchangeChain(t.Context(), card, testCommandChain())

			if err != io.ErrClosedPipe {
				t.Errorf("error = %v, want unchanged io.ErrClosedPipe", err)
			}
		})
	}
}

func TestExchangeChainRejectsMalformedResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
		response: []byte{0x90},
	}}}

	_, err := ExchangeChain(t.Context(), card, testCommandChain())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("error = %v, want ErrInvalidResponse", err)
	}
}

func TestExchangeChainLimitsFinalResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{
			command:  []byte{0x90, 0xda, 0x01, 0x02, 0x02, 0xaa, 0xbb},
			response: []byte{0x90, 0x00},
		},
		{
			command:  []byte{0x80, 0xda, 0x81, 0x03, 0x01, 0xcc, 0x00},
			response: []byte{0x01, 0x61, 0x02},
		},
		{
			command:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
			response: []byte{0x02, 0x03, 0x90, 0x00},
		},
	}}

	_, err := ExchangeChain(t.Context(), card, testCommandChain(), WithMaxResponseSize(2))

	if !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestExchangeChainRejectsInvalidOptionsBeforeIO(t *testing.T) {
	for _, tt := range []struct {
		name   string
		option ExchangeOption
	}{
		{name: "negative response limit", option: WithMaxResponseSize(-1)},
		{name: "empty status list", option: WithMoreDataStatusBytes()},
		{name: "unsupported status", option: WithMoreDataStatusBytes(0x91)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			card := &fakeCard{t: t}

			_, err := ExchangeChain(t.Context(), card, testCommandChain(), tt.option)

			if !errors.Is(err, ErrInvalidOption) {
				t.Errorf("error = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func testCommandChain() []Command {
	return []Command{
		{CLA: 0x90, INS: 0xda, P1: 0x01, P2: 0x02, Data: []byte{0xaa, 0xbb}, Encoding: EncodingShort},
		{CLA: 0x80, INS: 0xda, P1: 0x81, P2: 0x03, Data: []byte{0xcc}, Le: 256, Encoding: EncodingShort},
	}
}
