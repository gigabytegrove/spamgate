package transport

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"unicode/utf8"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// relayHeaderSection returns only RFC 5322 header octets, not the message
// body. A missing header/body separator is treated conservatively as all
// headers; malformed originals must not silently bypass SMTPUTF8 checks.
func relayHeaderSection(raw []byte) []byte {
	for pos := 0; pos < len(raw); {
		next := bytes.IndexByte(raw[pos:], '\n')
		if next < 0 {
			return raw
		}
		line := raw[pos : pos+next]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			return raw[:pos]
		}
		pos += next + 1
	}
	return raw
}

// inspectRelayHeader reports whether the immutable original contains
// internationalized RFC 6532 header fields. Eight-bit BODY data alone
// requires 8BITMIME but does not require SMTPUTF8. A malformed eight-bit
// header must never be forwarded as though it were valid UTF-8.
func inspectRelayHeader(raw []byte) (needsSMTPUTF8 bool, err error) {
	header := relayHeaderSection(raw)
	if bytes.IndexByte(header, 0) >= 0 {
		return false, errors.New("original RFC 5322 headers contain NUL")
	}
	if !containsEightBit(header) {
		return false, nil
	}
	if !utf8.Valid(header) {
		return false, errors.New("original RFC 5322 headers contain invalid UTF-8 octets")
	}
	return true, nil
}

// validateRelayEnvelope prevents a malformed persisted envelope from
// reaching the SMTP wire. The original reverse path may be empty or <> for
// DSNs; recipients must be nonempty. This deliberately does not rewrite
// or IDNA-normalize addresses, which could change the accepted recipient.
func validateRelayEnvelope(m core.Message) error {
	if len(m.Recipients) == 0 {
		return errors.New("SMTP relay has no recipients")
	}
	if err := validateRelayAddress(m.Sender, true); err != nil {
		return fmt.Errorf("invalid SMTP reverse path: %w", err)
	}
	for i, recipient := range m.Recipients {
		if err := validateRelayAddress(recipient, false); err != nil {
			return fmt.Errorf("invalid SMTP recipient %d: %w", i+1, err)
		}
	}
	return nil
}

func validateRelayAddress(address string, allowNull bool) error {
	if allowNull && (address == "" || address == "<>") {
		return nil
	}
	if address == "" {
		return errors.New("empty address")
	}
	if !utf8.ValidString(address) {
		return errors.New("invalid UTF-8 address")
	}
	for _, r := range address {
		switch r {
		case '\x00', '\r', '\n':
			return errors.New("control octet in address")
		}
	}
	// net/smtp formats paths as <address> without escaping. Require a
	// single bare RFC 5322 mailbox to prevent angle-bracket and ESMTP
	// parameter injection; quoted local parts remain valid.
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return errors.New("address is not a single bare mailbox")
	}
	// ParseAddress removes quoting from the local part. Compare against
	// its canonical mailbox rendering instead of parsed.Address, so
	// legitimate quoted local parts remain valid without allowing
	// display names, comments or injected ESMTP parameters.
	if (&mail.Address{Address: parsed.Address}).String() != "<"+address+">" {
		return errors.New("address is not a canonical bare mailbox")
	}
	return nil
}
