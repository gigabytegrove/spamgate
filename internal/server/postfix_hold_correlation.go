package server

import (
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// correlatesPostfixHold establishes a conservative, read-only association.
// Queue IDs can be reused. Complete, case-sensitive SMTP local-part identity,
// case-insensitive ASCII domain identity, and exact recipient multiplicity are
// required before a held original can be released by a privileged helper.
func correlatesPostfixHold(scan core.Message, held PostfixHeld) bool {
	if scan.Connector != "milter" || scan.MTAAction != "postfix_hold_requested" ||
		!validPostfixEvidenceID(held.QueueID) || scan.MTAQueueID != held.QueueID {
		return false
	}
	if scan.Timestamp.IsZero() || held.ArrivalTime <= 0 ||
		absDuration(scan.Timestamp.Sub(time.Unix(held.ArrivalTime, 0))) > 15*time.Minute {
		return false
	}
	scanSender, scanOK := postfixEnvelopeSenderKey(scan.Sender)
	heldSender, heldOK := postfixEnvelopeSenderKey(held.Sender)
	if !scanOK || !heldOK || scanSender != heldSender {
		return false
	}
	if held.RecipientsTruncated || held.RecipientCount != len(held.Recipients) ||
		len(held.Recipients) == 0 || len(scan.Recipients) != len(held.Recipients) {
		return false
	}
	remaining := make(map[string]int, len(scan.Recipients))
	for _, recipient := range scan.Recipients {
		key, ok := postfixEnvelopeMailboxKey(recipient)
		if !ok {
			return false
		}
		remaining[key]++
	}
	for _, recipient := range held.Recipients {
		key, ok := postfixEnvelopeMailboxKey(recipient)
		if !ok || remaining[key] == 0 {
			return false
		}
		remaining[key]--
	}
	return true
}
