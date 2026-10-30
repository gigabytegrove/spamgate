package transport

import (
	"errors"
	"fmt"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// containsEightBit reports whether bytes require an ESMTP 8BITMIME-capable
// next hop. Do not silently downgrade or re-encode the immutable original.
func containsEightBit(raw []byte) bool {
	for _, b := range raw {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

func requiresSMTPUTF8(m core.Message) bool {
	if containsEightBit([]byte(m.Sender)) {
		return true
	}
	for _, recipient := range m.Recipients {
		if containsEightBit([]byte(recipient)) {
			return true
		}
	}
	return false
}

// checkRelayCapabilities runs after the upstream greeting and any STARTTLS
// upgrade, but BEFORE MAIL FROM. Unsupported transport capabilities are
// retryable configuration errors: the durable original must stay in the queue
// for a compatible relay or an operator decision. Never silently downgrade
// SMTPUTF8 addresses or 8-bit message bytes.
func checkRelayCapabilities(client *smtp.Client, m core.Message, raw []byte) error {
	if client == nil {
		return errors.New("SMTP relay client is nil")
	}
	if containsEightBit(raw) {
		if ok, _ := client.Extension("8BITMIME"); !ok {
			return errors.New("relay lacks 8BITMIME required by original message")
		}
	}
	if requiresSMTPUTF8(m) {
		// RFC 6531 requires SMTPUTF8-capable relays to also implement
		// 8BITMIME. Do not entrust an internationalized envelope to a
		// peer advertising a contradictory, nonconformant capability set.
		if ok, _ := client.Extension("SMTPUTF8"); !ok {
			return errors.New("relay lacks SMTPUTF8 required by envelope address")
		}
		if ok, _ := client.Extension("8BITMIME"); !ok {
			return errors.New("relay advertises SMTPUTF8 without required 8BITMIME")
		}
	}
	if ok, advertised := client.Extension("SIZE"); ok {
		advertised = strings.TrimSpace(advertised)
		if advertised != "" {
			limit, err := strconv.ParseUint(advertised, 10, 64)
			if err != nil {
				return fmt.Errorf("relay advertised malformed SMTP SIZE limit: %w", err)
			}
			if limit > 0 && uint64(len(raw)) > limit {
				return fmt.Errorf("original message of %d bytes exceeds relay SMTP SIZE limit of %d", len(raw), limit)
			}
		}
	}
	return nil
}
