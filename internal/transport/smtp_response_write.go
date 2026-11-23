package transport

import (
 "bufio"
 "io"
 "net"
 "fmt"
 "time"
)

// smtpWriteResponse bounds writes independently of the command read deadline.
// In particular, a timeout reply must be writable after SetReadDeadline expires.
// Refresh the deadline on every response, including multiline EHLO responses,
// so a previously sent greeting cannot poison a later response.
func smtpWriteResponse(conn net.Conn, writer *bufio.Writer, response string) error {
 if err := validateSMTPResponseFrame(response); err != nil { return fmt.Errorf("invalid SMTP response frame: %w", err) }
 if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
  return err
 }
 if _, err := io.WriteString(writer, response); err != nil {
  return err
 }
 return writer.Flush()
}
