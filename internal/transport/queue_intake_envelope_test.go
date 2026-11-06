package transport

import (
 "context"
 "os"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestIntakeEnvelopeValidation(t *testing.T) {
 cases := []struct {
  name, sender string
  recipients []string
  valid bool
 }{
  {"ordinary", "sender@example.invalid", []string{"user@example.invalid"}, true},
  {"dsn reverse path", "", []string{"user@example.invalid"}, true},
  {"multiple recipients", "sender@example.invalid", []string{"a@example.invalid", "b@example.invalid"}, true},
  {"SMTPUTF8", "séndér@example.invalid", []string{"récepteur@example.invalid"}, true},
  {"missing recipients", "sender@example.invalid", nil, false},
  {"empty recipient", "sender@example.invalid", []string{""}, false},
  {"second empty recipient", "sender@example.invalid", []string{"a@example.invalid", ""}, false},
  {"recipient newline", "sender@example.invalid", []string{"a@example.invalid\r\nRCPT TO:<other@example.invalid>"}, false},
  {"recipient NUL", "sender@example.invalid", []string{"a\x00@example.invalid"}, false},
  {"recipient tab", "sender@example.invalid", []string{"a\t@example.invalid"}, false},
  {"recipient DEL", "sender@example.invalid", []string{"a\x7f@example.invalid"}, false},
  {"recipient SOH", "sender@example.invalid", []string{"a\x01@example.invalid"}, false},
  {"sender newline", "sender@example.invalid\nMAIL FROM:<other@example.invalid>", []string{"a@example.invalid"}, false},
  {"sender NUL", "sender\x00@example.invalid", []string{"a@example.invalid"}, false},
  {"sender tab", "sender\t@example.invalid", []string{"a@example.invalid"}, false},
  {"sender DEL", "sender\x7f@example.invalid", []string{"a@example.invalid"}, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   err := validateIntakeEnvelope(tc.sender, tc.recipients)
   if (err == nil) != tc.valid { t.Fatalf("valid=%t error=%v", tc.valid, err) }
  })
 }
}

func TestAllASCIIControlsRejected(t *testing.T) {
 for c := byte(0); c < 0x20; c++ {
  recipient := "a" + string([]byte{c}) + "@example.invalid"
  if err := validateIntakeEnvelope("", []string{recipient}); err == nil {
   t.Fatalf("recipient accepted ASCII control 0x%02x", c)
  }
  sender := "a" + string([]byte{c}) + "@example.invalid"
  if err := validateIntakeEnvelope(sender, []string{"b@example.invalid"}); err == nil {
   t.Fatalf("sender accepted ASCII control 0x%02x", c)
  }
 }
}

func TestRejectedIntakeEnvelopeDoesNotPersistOrRelay(t *testing.T) {
 sends := 0
 q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
  sends++
  return nil
 })
 for _, recipient := range []string{"", "user@example.invalid\r\nDATA", "user\x00@example.invalid", "user\t@example.invalid", "user\x7f@example.invalid"} {
  id := core.ID()
  msg := core.Message{ID: id, Sender: "sender@example.invalid", Recipients: []string{recipient}, Action: "accept"}
  if err := q.Enqueue(msg, []byte("Subject: test\r\n\r\nbody")); err == nil {
   t.Fatalf("unsafe recipient %q accepted", recipient)
  }
  if _, err := os.Stat(q.path(id)); !os.IsNotExist(err) {
   t.Fatalf("rejected recipient created durable record: %v", err)
  }
 }
 if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if sends != 0 { t.Fatalf("rejected mail was relayed %d times", sends) }
}

func TestMalformedUTF8EnvelopeRejectedWithoutPersistence(t *testing.T) {
 invalid := []struct {
  name string
  value string
 }{
  {"invalid leading byte", string([]byte{0xff}) + "@example.invalid"},
  {"truncated multibyte", "user@" + string([]byte{0xe2, 0x82})},
  {"overlong encoding", string([]byte{0xc0, 0xaf}) + "@example.invalid"},
  {"surrogate encoding", string([]byte{0xed, 0xa0, 0x80}) + "@example.invalid"},
 }
 sends := 0
 q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
  sends++
  return nil
 })
 for _, tc := range invalid {
  t.Run(tc.name, func(t *testing.T) {
   for _, sender := range []bool{true, false} {
    id := core.ID()
    msg := core.Message{ID: id, Sender: "sender@example.invalid", Recipients: []string{"user@example.invalid"}, Action: "accept"}
    if sender {
     msg.Sender = tc.value
    } else {
     msg.Recipients = []string{tc.value}
    }
    if err := q.Enqueue(msg, []byte("Subject: test\r\n\r\nbody")); err == nil {
     t.Fatal("malformed UTF-8 envelope accepted")
    }
    if _, err := os.Stat(q.path(id)); !os.IsNotExist(err) {
     t.Fatalf("rejected envelope created durable record: %v", err)
    }
   }
  })
 }
 if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if sends != 0 { t.Fatalf("rejected mail was relayed %d times", sends) }
}
