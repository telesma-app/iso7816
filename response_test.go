package iso7816

import (
	"bytes"
	"errors"
	"testing"
)

func TestResponseRoundTrip(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x90, 0x00}

	response, err := ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	raw[0] = 0xff

	if !bytes.Equal(response.Data, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("Data = %x", response.Data)
	}
	if response.Status != StatusSuccess {
		t.Errorf("Status = %s, want 9000", response.Status)
	}

	encoded, err := response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(encoded, []byte{0x01, 0x02, 0x03, 0x90, 0x00}) {
		t.Errorf("MarshalBinary = %x", encoded)
	}
}

func TestParseResponseRejectsMissingStatusWord(t *testing.T) {
	for _, raw := range [][]byte{nil, {0x90}} {
		if _, err := ParseResponse(raw); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseResponse(%x) error = %v, want ErrInvalidResponse", raw, err)
		}
	}
}

func TestStatusWord(t *testing.T) {
	status := NewStatusWord(0x6a, 0x82)
	if status.SW1() != 0x6a || status.SW2() != 0x82 {
		t.Errorf("status bytes = %02x %02x", status.SW1(), status.SW2())
	}
	if status.String() != "6a82" {
		t.Errorf("String = %q", status.String())
	}
	if status.IsSuccess() {
		t.Error("6a82 unexpectedly reports success")
	}
	if !StatusSuccess.IsSuccess() {
		t.Error("9000 does not report success")
	}
}

func TestStatusWordLengths(t *testing.T) {
	tests := []struct {
		name   string
		status StatusWord
		method func(StatusWord) (uint32, bool)
		want   uint32
		ok     bool
	}{
		{name: "more data", status: 0x6112, method: StatusWord.MoreDataLength, want: 0x12, ok: true},
		{name: "more data maximum", status: 0x6100, method: StatusWord.MoreDataLength, want: 256, ok: true},
		{name: "legacy more data", status: 0x9f08, method: StatusWord.MoreDataLength, want: 8, ok: true},
		{name: "not more data", status: 0x9000, method: StatusWord.MoreDataLength},
		{name: "correct length", status: 0x6c40, method: StatusWord.CorrectLength, want: 0x40, ok: true},
		{name: "correct maximum", status: 0x6c00, method: StatusWord.CorrectLength, want: 256, ok: true},
		{name: "not correct length", status: 0x6700, method: StatusWord.CorrectLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.method(tt.status)
			if got != tt.want || ok != tt.ok {
				t.Errorf("length = %d, %v, want %d, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestResponseAPDUError(t *testing.T) {
	if err := (Response{Status: StatusSuccess}).APDUError(); err != nil {
		t.Fatalf("success APDUError = %v", err)
	}

	err := (Response{Status: 0x6a82}).APDUError()
	var apduErr *APDUError
	if !errors.As(err, &apduErr) {
		t.Fatalf("error = %v, want *APDUError", err)
	}
	if apduErr.SW1 != 0x6a || apduErr.SW2 != 0x82 || apduErr.StatusWord() != 0x6a82 {
		t.Errorf("APDUError = %#v", apduErr)
	}
}
