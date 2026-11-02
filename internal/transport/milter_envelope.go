package transport

import (
	"bytes"
	"errors"
	"unicode"
	"unicode/utf8"
)

// milterEnvelopeAddress validates the libmilter envfrom/envrcpt argv wire
// representation: a NUL-terminated path followed by zero or more NUL-
// terminated ESMTP arguments. Never silently truncate an unterminated or
// ambiguous callback to a different sender/recipient identity.
func milterEnvelopeAddress(packet []byte, allowNull bool) (string, error) {
	if len(packet) < 2 || len(packet) > 4096 || packet[len(packet)-1] != 0 {
		return "", errors.New("invalid envelope callback length or terminator")
	}
	args := bytes.Split(packet[:len(packet)-1], []byte{0})
	if len(args) > 17 || len(args[0]) > 2048 {
		return "", errors.New("envelope callback exceeds argument limits")
	}
	path := args[0]
	if !utf8.Valid(path) {
		return "", errors.New("invalid UTF-8 in envelope address")
	}
	address := string(path)
	if len(address) >= 2 && address[0] == '<' && address[len(address)-1] == '>' {
		address = address[1 : len(address)-1]
	} else if bytes.ContainsAny(path, "<>") {
		return "", errors.New("unbalanced envelope path brackets")
	}
	if address == "" && (!allowNull || string(path) != "<>") {
		return "", errors.New("empty or invalid null reverse path")
	}
	for _, r := range address {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '<' || r == '>' {
			return "", errors.New("invalid character in envelope address")
		}
	}
	for _, arg := range args[1:] {
		if len(arg) == 0 || len(arg) > 256 {
			return "", errors.New("empty or oversized ESMTP argument")
		}
		for _, b := range arg {
			if b < 33 || b > 126 || b == '<' || b == '>' {
				return "", errors.New("invalid ESMTP argument byte")
			}
		}
	}
	return address, nil
}
