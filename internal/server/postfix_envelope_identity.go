package server

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// postfixEnvelopeMailboxKey is an authorization identity, not a mailbox
// delivery canonicalizer. SMTP local parts can be case-sensitive; folding
// them would permit a different mailbox to inherit a held scan's authority.
// Domain names are ASCII case-insensitive. Internationalized domains must
// already be represented as A-labels (IDNA) by the MTA; ambiguous forms
// deliberately fail closed instead of guessing an equivalence.
func postfixEnvelopeMailboxKey(address string) (string, bool) {
	if len(address) < 3 || len(address) > 254 || !utf8.ValidString(address) || strings.Count(address, "@") != 1 {
		return "", false
	}
	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 || at > 64 {
		return "", false
	}
	local, domain := address[:at], address[at+1:]
	for _, r := range local {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '<' || r == '>' || r == '\u2028' || r == '\u2029' {
			return "", false
		}
	}
	if len(domain) > 253 || strings.HasSuffix(domain, ".") {
		return "", false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || (c == '-' && i > 0 && i < len(label)-1)) {
				return "", false
			}
		}
	}
	return local + "@" + strings.ToLower(domain), true
}

// postfixEnvelopeSenderKey supports the two standard representations of the
// SMTP null reverse path, plus exactly one optional angle pair for a normal
// sender. strings.Trim("<>") is unsafe: it collapses malformed nested
// wrappers into an apparently valid identity.
func postfixEnvelopeSenderKey(sender string) (string, bool) {
	if sender == "" || sender == "<>" {
		return "<>", true
	}
	if strings.HasPrefix(sender, "<") && strings.HasSuffix(sender, ">") {
		sender = sender[1 : len(sender)-1]
	}
	return postfixEnvelopeMailboxKey(sender)
}
