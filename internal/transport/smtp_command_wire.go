package transport

// validSMTPCommandWire rejects malformed SMTP command framing before any
// envelope or session state is changed. RFC 5321 command lines use printable
// ASCII; CRLF is removed by readSMTPCommand. Internal spaces are preserved
// for MAIL/RCPT parameters and Postfix XFORWARD attributes.
func validSMTPCommandWire(line string) bool {
 if len(line) == 0 || len(line) > 512 || line[0] == ' ' || line[len(line)-1] == ' ' {
  return false
 }
 for i := 0; i < len(line); i++ {
  if line[i] < 0x20 || line[i] > 0x7e {
   return false
  }
 }
 // The command verb must be nonempty and made of ASCII letters.
 end := 0
 for end < len(line) && line[end] != ' ' { end++ }
 if end == 0 { return false }
 for i := 0; i < end; i++ {
  c := line[i]
  if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
   return false
  }
 }
 // Exactly one SP separates verb from arguments. A second SP can
 // accidentally create an empty path/identity after downstream trimming.
 if end < len(line) && (end+1 == len(line) || line[end+1] == ' ') {
  return false
 }
 return true
}
