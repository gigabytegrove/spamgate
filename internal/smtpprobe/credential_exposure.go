package smtpprobe

import "strings"

// credentialExposureFindings identifies credential-bearing AUTH mechanisms
// advertised on an unencrypted SMTP connection. It never sends credentials.
// An EHLO advertisement is not proof that the server accepts AUTH commands.
func credentialExposureFindings(r Result) []Finding {
	if r.EHLOCode != 250 || ambiguousAUTH(r.EHLOWarnings) {
		return nil
	}
	exposed := false
	for _, mechanism := range r.AuthMechanisms {
		switch strings.ToUpper(strings.TrimSpace(mechanism)) {
		case "PLAIN", "LOGIN":
			exposed = true
		}
	}
	if !exposed {
		return nil
	}
	return []Finding{{
		Code: "CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED",
		Severity: "warning",
		Message: "SMTP server advertises PLAIN or LOGIN before verified STARTTLS; confirm that cleartext credential submission is rejected by server policy",
	}}
}
