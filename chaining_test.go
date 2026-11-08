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

	commands, err := Chain(command, 8)

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

	commands, err := Chain(Command{Data: data}, 7)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	data[0] = 0xff

	if len(commands) != 1 || !bytes.Equal(commands[0].Data, []byte{0x01, 0x02}) {
		t.Errorf("commands = %#v", commands)
	}
}

func TestChainRejectsInvalidCommandAndFragmentSize(t *testing.T) {
	for _, test := range []struct {
		name    string
		command Command
		limit   int
		wantErr error
	}{
		{name: "chaining bit already set", command: Command{CLA: CommandChainingBit}, limit: 4, wantErr: ErrInvalidCommand},
		{name: "extended empty chaining bit", command: Command{CLA: CommandChainingBit, Encoding: EncodingExtended}, limit: 4, wantErr: ErrInvalidCommand},
		{name: "zero size", limit: 0, wantErr: ErrInvalidFragmentSize},
		{name: "invalid encoding", command: Command{Encoding: Encoding(99)}, limit: 256, wantErr: ErrInvalidCommand},
		{name: "invalid Le", command: Command{Le: maxExtendedResponseDataLength + 1}, limit: 256, wantErr: ErrInvalidCommand},
		{name: "invalid short Le", command: Command{Le: maxShortResponseDataLength + 1, Encoding: EncodingShort}, limit: 256, wantErr: ErrInvalidCommand},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Chain(test.command, test.limit)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Chain error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestChainBoundsEncodedFragments(t *testing.T) {
	for _, test := range []struct {
		name             string
		encoding         Encoding
		resolvedEncoding Encoding
		limit            int
		dataLength       int
		le               uint32
		fragments        []int
		apduLengths      []int
	}{
		{name: "short 256-byte limit", encoding: EncodingShort, resolvedEncoding: EncodingShort, limit: 256, dataLength: 257, le: 256, fragments: []int{250, 7}, apduLengths: []int{255, 13}},
		{name: "short final Le", encoding: EncodingShort, resolvedEncoding: EncodingShort, limit: 256, dataLength: 251, le: 256, fragments: []int{250, 1}, apduLengths: []int{255, 7}},
		{name: "short without Le", encoding: EncodingShort, resolvedEncoding: EncodingShort, limit: 256, dataLength: 252, fragments: []int{251, 1}, apduLengths: []int{256, 6}},
		{name: "short encoding cap", encoding: EncodingShort, resolvedEncoding: EncodingShort, limit: 2048, dataLength: 600, le: 256, fragments: []int{255, 255, 90}, apduLengths: []int{260, 260, 96}},
		{name: "extended configured limit", encoding: EncodingExtended, resolvedEncoding: EncodingExtended, limit: 512, dataLength: 1024, le: 65536, fragments: []int{503, 503, 18}, apduLengths: []int{510, 510, 27}},
		{name: "extended final Le", encoding: EncodingExtended, resolvedEncoding: EncodingExtended, limit: 512, dataLength: 505, le: 65536, fragments: []int{503, 2}, apduLengths: []int{510, 11}},
		{name: "extended small final capacity", encoding: EncodingExtended, resolvedEncoding: EncodingExtended, limit: 10, dataLength: 3, le: 65536, fragments: []int{1, 1, 1}, apduLengths: []int{8, 8, 10}},
		{name: "extended encoding cap", encoding: EncodingExtended, resolvedEncoding: EncodingExtended, limit: 65544, dataLength: 65536, le: 65536, fragments: []int{65535, 1}, apduLengths: []int{65542, 10}},
		{name: "auto short boundary", resolvedEncoding: EncodingShort, limit: 261, dataLength: 255, le: 256, fragments: []int{255}, apduLengths: []int{261}},
		{name: "auto extended data", resolvedEncoding: EncodingExtended, limit: 512, dataLength: 256, le: 256, fragments: []int{256}, apduLengths: []int{265}},
		{name: "auto extended response", resolvedEncoding: EncodingExtended, limit: 512, dataLength: 1, le: 257, fragments: []int{1}, apduLengths: []int{10}},
		{name: "auto retains extended fragments", resolvedEncoding: EncodingExtended, limit: 256, dataLength: 600, le: 256, fragments: []int{247, 247, 106}, apduLengths: []int{254, 254, 115}},
		{name: "case 1", resolvedEncoding: EncodingShort, limit: 4, fragments: []int{0}, apduLengths: []int{4}},
		{name: "short case 2", resolvedEncoding: EncodingShort, limit: 5, le: 256, fragments: []int{0}, apduLengths: []int{5}},
		{name: "extended case 2", encoding: EncodingExtended, resolvedEncoding: EncodingExtended, limit: 7, le: 65536, fragments: []int{0}, apduLengths: []int{7}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, test.dataLength)
			for i := range data {
				data[i] = byte(i)
			}
			command := Command{CLA: 0x80, INS: 0xda, P1: 0x7f, P2: 0x21, Data: data, Le: test.le, Encoding: test.encoding}

			commands, err := Chain(command, test.limit)
			if err != nil {
				t.Fatal(err)
			}
			if len(commands) != len(test.fragments) {
				t.Fatalf("fragments = %d, want %d", len(commands), len(test.fragments))
			}

			offset := 0
			for i, fragment := range commands {
				length := test.fragments[i]
				if !bytes.Equal(fragment.Data, data[offset:offset+length]) {
					t.Errorf("fragment %d data = %x, want input bytes %d:%d", i, fragment.Data, offset, offset+length)
				}
				offset += length

				cla, le := byte(0x90), uint32(0)
				if i == len(commands)-1 {
					cla, le = 0x80, test.le
				}
				if fragment.CLA != cla || fragment.Le != le || fragment.Encoding != test.resolvedEncoding ||
					fragment.INS != command.INS || fragment.P1 != command.P1 || fragment.P2 != command.P2 {
					t.Errorf("fragment %d header or encoding = %+v", i, fragment)
				}

				apdu, err := fragment.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(apdu) != test.apduLengths[i] || len(apdu) > test.limit {
					t.Errorf("fragment %d APDU length = %d, want %d within limit %d", i, len(apdu), test.apduLengths[i], test.limit)
				}
			}
			if offset != len(data) {
				t.Errorf("combined data length = %d, want %d", offset, len(data))
			}
		})
	}
}

func TestChainPreservesSnapshotOwnership(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 251)
	commands, err := Chain(Command{INS: 0xda, Data: data, Le: 256}, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 {
		t.Fatalf("fragments = %d, want 2", len(commands))
	}

	clear(data)
	commands[0].Data = append(commands[0].Data, 0xff)
	if !bytes.Equal(commands[0].Data, append(bytes.Repeat([]byte{0xab}, 250), 0xff)) || !bytes.Equal(commands[1].Data, []byte{0xab}) {
		t.Errorf("fragment snapshots changed: first %x, last %x", commands[0].Data, commands[1].Data)
	}
}

func TestChainRejectsInsufficientCapacity(t *testing.T) {
	for _, test := range []struct {
		name    string
		limit   int
		command Command
		wantErr error
	}{
		{name: "header", limit: 3, wantErr: ErrInvalidFragmentSize},
		{name: "short Le", limit: 4, command: Command{Le: 256}, wantErr: ErrInvalidFragmentSize},
		{name: "extended Le", limit: 6, command: Command{Le: 65536, Encoding: EncodingExtended}, wantErr: ErrInvalidFragmentSize},
		{name: "short data and Le", limit: 6, command: Command{Data: []byte{1}, Le: 256}, wantErr: ErrInvalidFragmentSize},
		{name: "extended data and Le", limit: 9, command: Command{Data: []byte{1}, Le: 65536, Encoding: EncodingExtended}, wantErr: ErrInvalidFragmentSize},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Chain(test.command, test.limit)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Chain = %v, want %v", err, test.wantErr)
			}
		})
	}
}
