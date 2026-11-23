package transport

import "errors"

// validateSMTPGreetingMailOptions enforces the RFC 5321 distinction between
// HELO (basic SMTP) and EHLO (ESMTP). An extension cannot be used merely
// because the server supports it: the client must negotiate EHLO first.
// The envelope parser separately validates every individual ESMTP option.
func validateSMTPGreetingMailOptions(esmtp bool, line string) error {
	if esmtp {
		return nil
	}
	_, options, err := parseSMTPPath(line, "MAIL FROM:", true)
	if err != nil {
		return err
	}
	if options != "" {
		return errors.New("MAIL extensions require EHLO")
	}
	return nil
}
