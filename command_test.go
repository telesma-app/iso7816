package iso7816

import (
	"bytes"
	"errors"
	"testing"
)

func TestCommandMarshalBinaryCases(t *testing.T) {
	tests := []struct {
		name    string
		command Command
		want    []byte
	}{
		{
			name:    "case 1",
			command: Command{CLA: 0x00, INS: 0x84, P1: 0x00, P2: 0x00},
			want:    []byte{0x00, 0x84, 0x00, 0x00},
		},
		{
			name:    "case 2 short",
			command: Command{CLA: 0x00, INS: 0x84, Le: 8},
			want:    []byte{0x00, 0x84, 0x00, 0x00, 0x08},
		},
		{
			name:    "case 2 short maximum",
			command: Command{CLA: 0x00, INS: 0x84, Le: 256},
			want:    []byte{0x00, 0x84, 0x00, 0x00, 0x00},
		},
		{
			name: "case 3 short",
			command: Command{
				CLA:  0x00,
				INS:  0xa4,
				P1:   0x04,
				Data: []byte{0xa0, 0x00, 0x00, 0x01},
			},
			want: []byte{0x00, 0xa4, 0x04, 0x00, 0x04, 0xa0, 0x00, 0x00, 0x01},
		},
		{
			name: "case 4 short",
			command: Command{
				CLA:  0x80,
				INS:  0x10,
				P1:   0x80,
				Data: []byte{0x04},
				Le:   256,
			},
			want: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		},
		{
			name: "case 2 extended",
			command: Command{
				CLA:      0x00,
				INS:      0xc0,
				Le:       65536,
				Encoding: EncodingExtended,
			},
			want: []byte{0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "case 3 extended",
			command: Command{
				CLA:      0x80,
				INS:      0xda,
				Data:     []byte{0x01, 0x02},
				Encoding: EncodingExtended,
			},
			want: []byte{0x80, 0xda, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02},
		},
		{
			name: "case 4 extended",
			command: Command{
				CLA:      0x80,
				INS:      0xda,
				Data:     []byte{0x01, 0x02},
				Le:       512,
				Encoding: EncodingExtended,
			},
			want: []byte{
				0x80, 0xda, 0x00, 0x00,
				0x00, 0x00, 0x02, 0x01, 0x02,
				0x02, 0x00,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.command.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestCommandMarshalBinaryAutoSelectsExtended(t *testing.T) {
	command := Command{
		CLA:  0x80,
		INS:  0xda,
		Data: bytes.Repeat([]byte{0xaa}, 256),
		Le:   257,
	}

	got, err := command.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	if got[4] != 0x00 || got[5] != 0x01 || got[6] != 0x00 {
		t.Fatalf("extended Lc prefix = %x, want 000100", got[4:7])
	}
	if !bytes.Equal(got[len(got)-2:], []byte{0x01, 0x01}) {
		t.Fatalf("extended Le suffix = %x, want 0101", got[len(got)-2:])
	}
}

func TestCommandMarshalBinaryRejectsInvalidLengthsAndEncoding(t *testing.T) {
	tests := []struct {
		name    string
		command Command
	}{
		{
			name:    "data beyond extended maximum",
			command: Command{Data: make([]byte, maxExtendedCommandDataLength+1)},
		},
		{
			name:    "Le beyond extended maximum",
			command: Command{Le: maxExtendedResponseDataLength + 1},
		},
		{
			name: "short data too long",
			command: Command{
				Data:     make([]byte, maxShortCommandDataLength+1),
				Encoding: EncodingShort,
			},
		},
		{
			name:    "short Le too large",
			command: Command{Le: maxShortResponseDataLength + 1, Encoding: EncodingShort},
		},
		{
			name:    "unknown encoding",
			command: Command{Encoding: Encoding(99)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.command.MarshalBinary()
			if !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("MarshalBinary error = %v, want ErrInvalidCommand", err)
			}
		})
	}
}
