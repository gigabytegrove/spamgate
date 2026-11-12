package smtpprobe

import "strings"

// capabilities interprets a successful EHLO response. The first line is the
// SMTP server's identity, never an extension (RFC 5321 section 4.1.1.1).
// Malformed advertisements are ignored instead of being promoted to evidence.
// The probe remains read-only and never sends AUTH or a mail transaction.
func capabilities(lines []string) (bool, []string) {
	startTLS := false
	auth := make([]string, 0)
	seen := make(map[string]bool)
	if len(lines) < 2 {
		return false, auth
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		keyword := strings.ToUpper(fields[0])
		switch {
		case keyword == "STARTTLS":
			// RFC 3207 STARTTLS is a bare extension without parameters.
			if len(fields) == 1 {
				startTLS = true
			}
		case keyword == "AUTH" || strings.HasPrefix(keyword, "AUTH="):
			tokens := fields[1:]
			if keyword != "AUTH" {
				tokens = append([]string{keyword[len("AUTH="):]}, tokens...)
			}
			for _, token := range tokens {
				if !validAuthMechanism(token) {
					continue
				}
				name := strings.ToUpper(token)
				if !seen[name] {
					seen[name] = true
					auth = append(auth, name)
				}
			}
		}
	}
	return startTLS, auth
}

func validAuthMechanism(token string) bool {
	if len(token) == 0 || len(token) > 40 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
