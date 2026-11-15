package smtpprobe

// containsSMTPWarning compares stable parser diagnostic codes without
// interpreting untrusted SMTP response text.
func containsSMTPWarning(warnings []string, code string) bool {
	for _, warning := range warnings {
		if warning == code {
			return true
		}
	}
	return false
}
