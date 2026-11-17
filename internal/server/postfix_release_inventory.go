package server

import (
    "errors"
    "strings"
    "unicode"
    "unicode/utf8"
)

// validPostfixEnvelopeEvidence accepts an empty reverse path only for senders
// (delivery status notifications). Control bytes, DEL, oversized and padded
// values cannot be trusted for privileged queue ownership comparisons.
// Literal backslashes remain valid evidence and are not escape-decoded.
func validPostfixEnvelopeEvidence(address string, allowEmpty bool) bool {
    if len(address) > 1024 || !utf8.ValidString(address) || strings.TrimSpace(address) != address {
        return false
    }
    if address == "" {
        return allowEmpty
    }
    for i := 0; i < len(address); i++ {
        if address[i] < 0x20 || address[i] == 0x7f {
            return false
        }
    }
    // Preserve valid internationalized SMTPUTF8 mailboxes, but refuse Unicode
    // format/control characters that can disguise envelope identities in UI
    // and privileged release audit records.
    for _, r := range address {
        if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
            return false
        }
    }
    return true
}

// validatePostfixReleaseInventory rejects ambiguous inventory supplied by
// either the native postqueue reader or an injected provider. A queue ID is
// only usable as authorization evidence if it occurs exactly once globally.
func validatePostfixReleaseInventory(items []PostfixHeld) error {
    if len(items) > 1000 {
        return errors.New("Postfix HOLD inventory exceeds safe entry limit")
    }
    seen := make(map[string]struct{}, len(items))
    for _, item := range items {
        if !validPostfixEvidenceID(item.QueueID) || strings.EqualFold(item.QueueID, "ALL") {
            return errors.New("invalid Postfix queue inventory identifier")
        }
        if _, exists := seen[item.QueueID]; exists {
            return errors.New("ambiguous Postfix queue inventory identifier")
        }
        seen[item.QueueID] = struct{}{}
        if !validPostfixEnvelopeEvidence(item.Sender, true) {
            return errors.New("invalid Postfix queue sender evidence")
        }
        if item.ArrivalTime <= 0 || item.MessageSize < 0 || item.RecipientCount < 1 ||
            item.RecipientsTruncated || item.RecipientCount > 50 || item.RecipientCount != len(item.Recipients) {
            return errors.New("incomplete Postfix queue ownership inventory")
        }
        for _, address := range item.Recipients {
            if !validPostfixEnvelopeEvidence(address, false) {
                return errors.New("invalid Postfix queue recipient evidence")
            }
        }
    }
    return nil
}
