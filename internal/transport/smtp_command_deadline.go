package transport

import "time"

// smtpCommandDeadline bounds an idle command read without ever extending the
// absolute SMTP session deadline. The caller applies it to the connection.
func smtpCommandDeadline(now, sessionDeadline time.Time, idleLimit time.Duration) time.Time {
	if idleLimit <= 0 || !now.Before(sessionDeadline) {
		return sessionDeadline
	}
	idleDeadline := now.Add(idleLimit)
	if idleDeadline.Before(sessionDeadline) {
		return idleDeadline
	}
	return sessionDeadline
}
