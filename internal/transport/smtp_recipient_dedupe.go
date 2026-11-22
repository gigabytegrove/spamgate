package transport

import "strings"

// sameSMTPRecipient preserves the case-sensitive local part while comparing
// DNS domains case-insensitively. Do not rewrite the first accepted address:
// it is the address that must be persisted and forwarded.
func sameSMTPRecipient(a, b string) bool {
    ai, bi := strings.LastIndexByte(a, '@'), strings.LastIndexByte(b, '@')
    if ai <= 0 || bi <= 0 || ai == len(a)-1 || bi == len(b)-1 {
        // Malformed historical records are not silently normalized.
        return a == b
    }
    return a[:ai] == b[:bi] && equalASCIIDNSDomain(a[ai+1:], b[bi+1:])
}

func containsSMTPRecipient(recipients []string, address string) bool {
    for _, existing := range recipients {
        if sameSMTPRecipient(existing, address) {
            return true
        }
    }
    return false
}

// Preserve the first address and order; never strip plus tags or fold the
// local part. Domain case is not part of mailbox identity.
func appendUniqueSMTPRecipient(recipients []string, address string) []string {
    if containsSMTPRecipient(recipients, address) {
        return recipients
    }
    return append(recipients, address)
}

func uniqueSMTPRecipients(recipients []string) []string {
    if len(recipients) < 2 {
        return recipients
    }
    unique := make([]string, 0, len(recipients))
    for _, recipient := range recipients {
        unique = appendUniqueSMTPRecipient(unique, recipient)
    }
    return unique
}

// Exact local-part duplicates with differently cased domains remain accepted
// at capacity; genuinely new mailboxes cannot mutate the accepted envelope.
func acceptSMTPRecipient(recipients []string, address string, maxDistinct int) ([]string, bool) {
    if containsSMTPRecipient(recipients, address) {
        return recipients, true
    }
    if maxDistinct <= 0 || len(recipients) >= maxDistinct {
        return recipients, false
    }
    return append(recipients, address), true
}

// DNS wire names are ASCII. Unicode case folding can equate unrelated UTF-8
// code points (for example the Kelvin sign and ASCII K), silently merging
// distinct historical envelope recipients. Internationalized domains must be
// canonicalized to IDNA A-labels by the envelope parser, not here.
func equalASCIIDNSDomain(a, b string) bool {
    if len(a) != len(b) { return false }
    for i := 0; i < len(a); i++ {
        x, y := a[i], b[i]
        if x >= 'A' && x <= 'Z' { x += 'a' - 'A' }
        if y >= 'A' && y <= 'Z' { y += 'a' - 'A' }
        if x != y { return false }
    }
    return true
}
