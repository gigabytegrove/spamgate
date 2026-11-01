package transport

import (
 "bufio"
 "errors"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestSMTPMailParametersAndUnadvertisedSMTPUTF8(t *testing.T) {
 tests := []struct {
  name, line string
  size int64
  eightBit, valid bool
 }{
  {"default", "MAIL FROM:<sender@example.org>", -1, false, true},
  {"null_reverse_path", "MAIL FROM:<>", -1, false, true},
  {"size_zero", "MAIL FROM:<sender@example.org> SIZE=0", 0, false, true},
  {"eight_bit", "MAIL FROM:<sender@example.org> BODY=8BITMIME SIZE=10485760", 10485760, true, true},
  {"explicit_seven_bit", "MAIL FROM:<sender@example.org> BODY=7BIT", -1, false, true},
  {"utf8_sender", "MAIL FROM:<büro@example.org>", 0, false, false},
  {"utf8_domain", "MAIL FROM:<sender@exämple.org>", 0, false, false},
  {"duplicate_size", "MAIL FROM:<sender@example.org> SIZE=0 SIZE=2", 0, false, false},
  {"duplicate_body", "MAIL FROM:<sender@example.org> BODY=7BIT BODY=8BITMIME", 0, false, false},
  {"unsupported_smtputf8", "MAIL FROM:<sender@example.org> SMTPUTF8", 0, false, false},
 }
 for _, tc := range tests {
  t.Run(tc.name, func(t *testing.T) {
   _, params, err := parseSMTPMailParameters(tc.line)
   if (err == nil) != tc.valid { t.Fatalf("unexpected parse result: %+v %v", params, err) }
   if tc.valid && (params.DeclaredSize != tc.size || params.EightBit != tc.eightBit) {
    t.Fatalf("lost ESMTP declaration: %+v", params)
   }
  })
 }
 for _, address := range []string{"RCPT TO:<büro@example.org>", "RCPT TO:<recipient@exämple.org>"} {
  if _, err := parseSMTPRecipient(address); err == nil { t.Fatalf("accepted unadvertised SMTPUTF8: %s", address) }
 }
}

func TestSMTPDATAContractPreventsUndeclaredContent(t *testing.T) {
 tests := []struct {
  name string
  params smtpMailParameters
  data string
  want error
 }{
  {"default_7bit", smtpMailParameters{DeclaredSize:-1}, "Subject: test\r\n\r\nhello\r\n", nil},
  {"exact_size", smtpMailParameters{DeclaredSize:4}, "1234", nil},
  {"underdeclared_size", smtpMailParameters{DeclaredSize:4}, "12345", errSMTPDeclaredSize},
  {"zero_declared_size", smtpMailParameters{DeclaredSize:0}, "x", errSMTPDeclaredSize},
  {"default_rejects_8bit", smtpMailParameters{DeclaredSize:-1}, "caf\u00e9", errSMTPBody7Bit},
  {"explicit_7bit_rejects_8bit", smtpMailParameters{DeclaredSize:-1, EightBit:false}, "caf\u00e9", errSMTPBody7Bit},
  {"eightbit_accepts_8bit", smtpMailParameters{DeclaredSize:-1, EightBit:true}, "caf\u00e9", nil},
  {"eightbit_still_checks_size", smtpMailParameters{DeclaredSize:3, EightBit:true}, "caf\u00e9", errSMTPDeclaredSize},
  {"utf8_header_requires_smtputf8", smtpMailParameters{DeclaredSize:-1, EightBit:true}, "Subject: caf\u00e9\\r\\n\\r\\nbody", errSMTPHeaderUTF8},
  {"invalid_utf8_header_rejected", smtpMailParameters{DeclaredSize:-1, EightBit:true}, "Subject: \\xff\\r\\n\\r\\nbody", errSMTPHeaderUTF8},
  {"encoded_header_eightbit_body", smtpMailParameters{DeclaredSize:-1, EightBit:true}, "Subject: =?UTF-8?Q?caf=C3=A9?=\\r\\n\\r\\ncaf\u00e9", nil},
 }
 for _, tc := range tests {
  t.Run(tc.name, func(t *testing.T) {
   got := validateSMTPDataContract(tc.params, []byte(tc.data))
   if !errors.Is(got, tc.want) { t.Fatalf("contract error = %v, want %v", got, tc.want) }
  })
 }
}

// A real loopback SMTP exchange proves that both failures occur before
// Scanner.Scan or Queue.Enqueue. Neither subsystem is attached in this test:
// reaching one would panic instead of acknowledging an invalid transaction.
func TestSMTPMailContractWireRefusesBeforeDurableAcceptance(t *testing.T) {
 store, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete=true; return nil }); err != nil { t.Fatal(err) }
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 _, trusted, _ := net.ParseCIDR("127.0.0.1/32")
 srv := &SMTP{Store:store, CIDRs:[]*net.IPNet{trusted}, Domains:[]string{"example.org"}}
 done := make(chan struct{})
 go func() {
  defer close(done)
  peer, err := listener.Accept()
  if err == nil { srv.handle(peer) }
 }()
 conn, err := net.Dial("tcp", listener.Addr().String())
 if err != nil { t.Fatal(err) }
 defer conn.Close()
 if err := conn.SetDeadline(time.Now().Add(10*time.Second)); err != nil { t.Fatal(err) }
 reader := bufio.NewReader(conn)
 read := func(want string) {
  t.Helper()
  line, err := reader.ReadString('\n')
  if err != nil || !strings.HasPrefix(line, want) { t.Fatalf("wanted %q, got %q (%v)", want, line, err) }
 }
 send := func(command, want string) {
  t.Helper()
  if _, err := fmt.Fprintf(conn, "%s\r\n", command); err != nil { t.Fatal(err) }
  read(want)
 }
 read("220 ")
 send("HELO relay.example.org", "250 ")
 send("MAIL FROM:<sender@example.org> SIZE=4", "250 ")
 send("RCPT TO:<recipient@example.org>", "250 ")
 send("DATA", "354 ")
 if _, err := fmt.Fprint(conn, "Subject: too large\r\n\r\nbody\r\n.\r\n"); err != nil { t.Fatal(err) }
 read("552 ")
 send("RCPT TO:<recipient@example.org>", "503 ")
 send("MAIL FROM:<sender@example.org> BODY=7BIT", "250 ")
 send("RCPT TO:<recipient@example.org>", "250 ")
 send("DATA", "354 ")
 if _, err := fmt.Fprint(conn, "Subject: test\r\n\r\ncaf\u00e9\r\n.\r\n"); err != nil { t.Fatal(err) }
 read("554 ")
 send("DATA", "503 ")
 send("MAIL FROM:<sender@example.org> BODY=8BITMIME", "250 ")
 send("RCPT TO:<recipient@example.org>", "250 ")
 send("DATA", "354 ")
 if _, err := fmt.Fprint(conn, "Subject: caf\u00e9\\r\\n\\r\\nbody\\r\\n.\\r\\n"); err != nil { t.Fatal(err) }
 read("554 ")
 send("MAIL FROM:<büro@example.org>", "501 ")
 send("RCPT TO:<recipient@example.org>", "503 ")
 send("MAIL FROM:<sender@example.org>", "250 ")
 send("RCPT TO:<büro@example.org>", "501 ")
 send("RSET", "250 ")
 send("QUIT", "221 ")
 <-done
 if got := store.List(10, ""); len(got) != 0 { t.Fatalf("invalid SMTP originals reached scan history: %+v", got) }
}
