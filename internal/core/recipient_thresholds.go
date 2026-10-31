package core

import "strings"

// RecipientThresholdSelection describes the only thresholds safely usable for
// a whole SMTP/Milter transaction. It never splits or modifies the envelope.
type RecipientThresholdSelection struct {
	TagThreshold, QuarantineThreshold, RejectThreshold float64
	Source, Detail string
}
func sameThresholds(a, b RecipientThresholdSelection) bool {
	return a.TagThreshold == b.TagThreshold && a.QuarantineThreshold == b.QuarantineThreshold && a.RejectThreshold == b.RejectThreshold
}

// SelectRecipientThresholds resolves every recipient's effective policy.
// Conflicting effective policies always use the global thresholds, because
// the Milter cannot issue distinct final DATA dispositions per recipient.
func SelectRecipientThresholds(s Settings, policies []RecipientPolicy, recipients []string) RecipientThresholdSelection {
	global := RecipientThresholdSelection{s.TagThreshold, s.QuarantineThreshold, s.RejectThreshold, "global", "Global policy"}
	if len(recipients) == 0 || len(policies) == 0 { return global }
	var first RecipientThresholdSelection
	matched, uniform, sameMailbox := 0, true, true
	for i, address := range recipients {
		effective := global
		for _, policy := range policies {
			if strings.EqualFold(address, policy.Mailbox) {
				effective.TagThreshold, effective.QuarantineThreshold, effective.RejectThreshold = policy.TagThreshold, policy.QuarantineThreshold, policy.RejectThreshold
				matched++
				break
			}
		}
		if i == 0 { first = effective } else {
			if !sameThresholds(first, effective) { uniform = false }
			if !strings.EqualFold(recipients[0], address) { sameMailbox = false }
		}
	}
	if !uniform {
		global.Source = "global_multi_recipient"
		global.Detail = "Conflicting effective recipient thresholds; global thresholds used for multi-recipient transaction; split message by MTA for distinct mailbox actions"
		return global
	}
	if matched == 0 || sameThresholds(first, global) { return global }
	first.Source = "mailbox_shared"
	first.Detail = "Uniform effective mailbox thresholds across all envelope recipients"
	if len(recipients) == 1 || sameMailbox {
		first.Source = "mailbox"
		first.Detail = "Mailbox-specific thresholds for " + recipients[0]
	}
	return first
}
