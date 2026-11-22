package transport

// validSMTPAuthorizationLocalPart is a defensive authorization boundary,
// not a substitute for the SMTP path parser. It intentionally permits quoted
// local parts and non-ASCII mailbox bytes already accepted by the parser,
// but refuses bytes that can change framing or represent an SMTP path delimiter.
// Do not trim or normalize the mailbox: local-part identity is case-sensitive.
func validSMTPAuthorizationLocalPart(local string) bool {
	if len(local) == 0 || len(local) > 64 {
		return false
	}
	for i := 0; i < len(local); i++ {
		switch b := local[i]; {
		case b < 0x20, b == 0x7f:
			return false
		case b == '<', b == '>':
			return false
		}
	}
	return true
}
