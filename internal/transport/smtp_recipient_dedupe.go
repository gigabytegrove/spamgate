package transport

// containsSMTPRecipient uses exact mailbox identity: local parts may be
// case-sensitive, and plus-addresses are distinct delivery targets.
func containsSMTPRecipient(recipients []string, address string) bool {
	for _, existing := range recipients {
		if existing == address {
			return true
		}
	}
	return false
}

// appendUniqueSMTPRecipient preserves the first occurrence of an exact SMTP
// mailbox. SMTP local parts can be case-sensitive, so do not fold case or
// strip plus-addressing. Domain normalization is deliberately left to the
// envelope parser; this helper never rewrites a delivery address.
func appendUniqueSMTPRecipient(recipients []string, address string) []string {
	if containsSMTPRecipient(recipients, address) {
		return recipients
	}
	return append(recipients, address)
}

// uniqueSMTPRecipients removes exact duplicates from legacy persisted
// envelopes without changing the order of distinct delivery targets.
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
