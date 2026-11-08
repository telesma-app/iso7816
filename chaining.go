package iso7816

import (
	"fmt"
	"slices"
)

// CommandChainingBit is the CLA bit set on every non-final command fragment.
const CommandChainingBit byte = 0x10

// Chain splits a command so each encoded APDU fits maxAPDULength, including its
// header, Lc and Le. All fragments use the same data limit, reserving room for
// the final Le. The limit must hold the required fields; case 1 commands need
// only their four-byte header.
//
// EncodingAuto chooses short encoding when the original command's data and Le
// fit short length fields, otherwise extended encoding. All fragments retain
// that choice. Intermediate fragments set CommandChainingBit and omit Le; the
// final fragment retains the original Le.
//
// Returned data are owned snapshots. Changing or appending one fragment's data
// does not affect the original command or another fragment.
func Chain(command Command, maxAPDULength int) ([]Command, error) {
	if command.CLA&CommandChainingBit != 0 {
		return nil, fmt.Errorf("%w: CLA already has command-chaining bit set", ErrInvalidCommand)
	}
	if maxAPDULength < 4 {
		return nil, fmt.Errorf("%w: maximum command APDU length %d cannot hold the header", ErrInvalidFragmentSize, maxAPDULength)
	}
	if command.Le > maxExtendedResponseDataLength {
		return nil, fmt.Errorf("%w: Le %d exceeds %d", ErrInvalidCommand, command.Le, maxExtendedResponseDataLength)
	}

	if command.Encoding == EncodingAuto {
		command.Encoding = EncodingShort
		if len(command.Data) > maxShortCommandDataLength || command.Le > maxShortResponseDataLength {
			command.Encoding = EncodingExtended
		}
	}

	var lcLength, leLength, maxDataLength int
	switch command.Encoding {
	case EncodingShort:
		if command.Le > maxShortResponseDataLength {
			return nil, fmt.Errorf("%w: Le %d exceeds short APDU limit %d", ErrInvalidCommand, command.Le, maxShortResponseDataLength)
		}
		lcLength, leLength, maxDataLength = 1, 1, maxShortCommandDataLength
	case EncodingExtended:
		lcLength, leLength, maxDataLength = 3, 2, maxExtendedCommandDataLength
	default:
		return nil, fmt.Errorf("%w: unknown encoding %d", ErrInvalidCommand, command.Encoding)
	}

	if len(command.Data) == 0 {
		length := 4
		if command.Le != 0 {
			length += lcLength // An extended case 2 APDU includes the 00 marker.
		}
		if length > maxAPDULength {
			return nil, fmt.Errorf("%w: command requires %d bytes, maximum %d", ErrInvalidFragmentSize, length, maxAPDULength)
		}

		command.Data = slices.Clone(command.Data)
		return []Command{command}, nil
	}

	overhead := 4 + lcLength
	if command.Le != 0 {
		overhead += leLength
	}
	fragmentLength := min(maxDataLength, maxAPDULength-overhead)
	if fragmentLength < 1 {
		return nil, fmt.Errorf("%w: maximum command APDU length %d cannot hold command data and length fields", ErrInvalidFragmentSize, maxAPDULength)
	}

	commands := make([]Command, 0, (len(command.Data)-1)/fragmentLength+1)
	remaining := command.Data
	for len(remaining) > fragmentLength {
		fragment := command
		fragment.CLA |= CommandChainingBit
		fragment.Le = 0
		fragment.Data = slices.Clone(remaining[:fragmentLength])
		commands = append(commands, fragment)
		remaining = remaining[fragmentLength:]
	}

	command.Data = slices.Clone(remaining)
	commands = append(commands, command)

	return commands, nil
}
