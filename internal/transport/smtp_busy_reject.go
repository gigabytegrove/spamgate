package transport

import "net"

// rejectBusySMTPConnection drops excess connections without attempting a
// potentially blocking SMTP write on the listener's accept goroutine.
// SMTP clients treat a closed connection before the greeting as a temporary
// transport failure and retry according to their own delivery policy.
func rejectBusySMTPConnection(conn net.Conn) {
 if conn != nil {
  _ = conn.Close()
 }
}
