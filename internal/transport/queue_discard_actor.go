package transport

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// validateQueueDiscardActor rejects characters that can forge or obscure
// an operator audit identity. Unicode letters are supported; invisible
// formatting characters and non-ASCII whitespace are not.
func validateQueueDiscardActor(actor string) (string, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" || len(actor) > 128 || !utf8.ValidString(actor) {
		return "", errors.New("valid audit actor required")
	}
	for _, r := range actor {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) ||
			(unicode.IsSpace(r) && r != ' ') {
			return "", errors.New("valid audit actor required")
		}
	}
	return actor, nil
}
