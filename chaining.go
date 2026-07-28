package iso7816

import (
	"fmt"
	"slices"
)

// CommandChainingBit is the CLA bit set on every non-final command fragment.
const CommandChainingBit byte = 0x10

// Chain splits command data into ISO 7816 command-chaining fragments. Each
// intermediate command has CommandChainingBit set and omits Le. The final
// command retains the original Le.
func Chain(command Command, maxDataLength int) ([]Command, error) {
	if command.CLA&CommandChainingBit != 0 {
		return nil, fmt.Errorf("%w: CLA already has command-chaining bit set", ErrInvalidCommand)
	}
	if maxDataLength < 1 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidFragmentSize, maxDataLength)
	}

	switch command.Encoding {
	case EncodingAuto, EncodingExtended:
		if maxDataLength > maxExtendedCommandDataLength {
			return nil, fmt.Errorf(
				"%w: %d exceeds extended APDU limit %d",
				ErrInvalidFragmentSize,
				maxDataLength,
				maxExtendedCommandDataLength,
			)
		}
	case EncodingShort:
		if command.Le > maxShortResponseDataLength {
			return nil, fmt.Errorf(
				"%w: Le %d exceeds short APDU limit %d",
				ErrInvalidCommand,
				command.Le,
				maxShortResponseDataLength,
			)
		}
		if maxDataLength > maxShortCommandDataLength {
			return nil, fmt.Errorf(
				"%w: %d exceeds short APDU limit %d",
				ErrInvalidFragmentSize,
				maxDataLength,
				maxShortCommandDataLength,
			)
		}
	default:
		return nil, fmt.Errorf("%w: unknown encoding %d", ErrInvalidCommand, command.Encoding)
	}
	if command.Le > maxExtendedResponseDataLength {
		return nil, fmt.Errorf(
			"%w: Le %d exceeds %d",
			ErrInvalidCommand,
			command.Le,
			maxExtendedResponseDataLength,
		)
	}

	if len(command.Data) <= maxDataLength {
		command.Data = slices.Clone(command.Data)
		return []Command{command}, nil
	}

	commands := make([]Command, 0, (len(command.Data)+maxDataLength-1)/maxDataLength)
	remaining := command.Data
	for len(remaining) > maxDataLength {
		commands = append(commands, Command{
			CLA:      command.CLA | CommandChainingBit,
			INS:      command.INS,
			P1:       command.P1,
			P2:       command.P2,
			Data:     slices.Clone(remaining[:maxDataLength]),
			Encoding: command.Encoding,
		})
		remaining = remaining[maxDataLength:]
	}
	command.Data = slices.Clone(remaining)
	commands = append(commands, command)

	return commands, nil
}
