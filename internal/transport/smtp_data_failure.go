package transport

import "errors"

// smtpDataReadFailureReply maps DATA framing failures to a protocol response.
// The caller MUST close the connection after sending the response. A read
// failure does not prove that the SMTP command stream is synchronized.
func smtpDataReadFailureReply(err error) (int, string) {
 if errors.Is(err, errSMTPDataTooLarge) {
  return 552, "5.3.4 Message too large"
 }
 return 554, "5.6.0 Invalid SMTP DATA framing"
}
