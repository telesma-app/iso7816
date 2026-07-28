package iso7816

import (
	"bytes"
	"errors"
	"testing"
)

func TestChainSplitsCommandAndRetainsFinalLe(t *testing.T) {
	command := Command{
		CLA:      0x80,
		INS:      0xda,
		P1:       0x01,
		P2:       0x02,
		Data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		Le:       256,
		Encoding: EncodingShort,
	}

	commands, err := Chain(command, 2)

	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("len(commands) = %d, want 3", len(commands))
	}

	for i, wantData := range [][]byte{{0x01, 0x02}, {0x03, 0x04}, {0x05}} {
		if !bytes.Equal(commands[i].Data, wantData) {
			t.Errorf("commands[%d].Data = %x, want %x", i, commands[i].Data, wantData)
		}
		if commands[i].INS != command.INS ||
			commands[i].P1 != command.P1 ||
			commands[i].P2 != command.P2 ||
			commands[i].Encoding != command.Encoding {
			t.Errorf("commands[%d] did not retain command fields", i)
		}
	}
	if commands[0].CLA != 0x90 || commands[1].CLA != 0x90 || commands[2].CLA != 0x80 {
		t.Errorf("fragment classes = %02x %02x %02x", commands[0].CLA, commands[1].CLA, commands[2].CLA)
	}
	if commands[0].Le != 0 || commands[1].Le != 0 || commands[2].Le != 256 {
		t.Errorf("fragment Le = %d %d %d", commands[0].Le, commands[1].Le, commands[2].Le)
	}
}

func TestChainClonesDataWithoutUnnecessaryFragment(t *testing.T) {
	data := []byte{0x01, 0x02}

	commands, err := Chain(Command{Data: data}, 2)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	data[0] = 0xff

	if len(commands) != 1 || !bytes.Equal(commands[0].Data, []byte{0x01, 0x02}) {
		t.Errorf("commands = %#v", commands)
	}
}

func TestChainRejectsInvalidCommandAndFragmentSize(t *testing.T) {
	tests := []struct {
		name    string
		command Command
		size    int
		wantErr error
	}{
		{
			name:    "chaining bit already set",
			command: Command{CLA: CommandChainingBit},
			size:    1,
			wantErr: ErrInvalidCommand,
		},
		{
			name:    "zero size",
			command: Command{},
			size:    0,
			wantErr: ErrInvalidFragmentSize,
		},
		{
			name:    "short fragment too large",
			command: Command{Encoding: EncodingShort},
			size:    maxShortCommandDataLength + 1,
			wantErr: ErrInvalidFragmentSize,
		},
		{
			name:    "extended fragment too large",
			command: Command{Encoding: EncodingExtended},
			size:    maxExtendedCommandDataLength + 1,
			wantErr: ErrInvalidFragmentSize,
		},
		{
			name:    "invalid encoding",
			command: Command{Encoding: Encoding(99)},
			size:    1,
			wantErr: ErrInvalidCommand,
		},
		{
			name:    "invalid Le",
			command: Command{Le: maxExtendedResponseDataLength + 1},
			size:    1,
			wantErr: ErrInvalidCommand,
		},
		{
			name:    "invalid short Le",
			command: Command{Le: maxShortResponseDataLength + 1, Encoding: EncodingShort},
			size:    1,
			wantErr: ErrInvalidCommand,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Chain(tt.command, tt.size)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Chain error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
