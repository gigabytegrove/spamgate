package server

import (
    "strings"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// correlatesPostfixHold establishes a conservative, read-only association.
// Postfix queue IDs are reusable, and a partial recipient match is not enough
// to authorize release of a multi-recipient message.
func correlatesPostfixHold(scan core.Message, held PostfixHeld) bool {
    if scan.Connector != "milter" || scan.MTAAction != "postfix_hold_requested" ||
        !validPostfixEvidenceID(held.QueueID) || scan.MTAQueueID != held.QueueID {
        return false
    }
    if scan.Timestamp.IsZero() || held.ArrivalTime <= 0 ||
        absDuration(scan.Timestamp.Sub(time.Unix(held.ArrivalTime, 0))) > 15*time.Minute {
        return false
    }
    if !strings.EqualFold(strings.Trim(scan.Sender, "<>"), strings.Trim(held.Sender, "<>")) {
        return false
    }
    if held.RecipientsTruncated || held.RecipientCount != len(held.Recipients) ||
        len(held.Recipients) == 0 || len(scan.Recipients) != len(held.Recipients) {
        return false
    }
    // Count occurrences, not merely membership. Duplicate addresses and
    // partial subsets must never be mistaken for the same SMTP envelope.
    remaining := make(map[string]int, len(scan.Recipients))
    for _, recipient := range scan.Recipients {
        if recipient == "" {
            return false
        }
        remaining[strings.ToLower(recipient)]++
    }
    for _, recipient := range held.Recipients {
        if recipient == "" {
            return false
        }
        key := strings.ToLower(recipient)
        if remaining[key] == 0 {
            return false
        }
        remaining[key]--
    }
    return true
}
