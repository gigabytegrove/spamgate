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
  {"missing recipients", "sender@example.invalid", nil, false},
  {"empty recipient", "sender@example.invalid", []string{""}, false},
  {"second empty recipient", "sender@example.invalid", []string{"a@example.invalid", ""}, false},
  {"recipient newline", "sender@example.invalid", []string{"a@example.invalid\r\nRCPT TO:<other@example.invalid>"}, false},
  {"recipient NUL", "sender@example.invalid", []string{"a\x00@example.invalid"}, false},
  {"sender newline", "sender@example.invalid\nMAIL FROM:<other@example.invalid>", []string{"a@example.invalid"}, false},
  {"sender NUL", "sender\x00@example.invalid", []string{"a@example.invalid"}, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   err := validateIntakeEnvelope(tc.sender, tc.recipients)
   if (err == nil) != tc.valid { t.Fatalf("valid=%t error=%v", tc.valid, err) }
  })
 }
}

func TestRejectedIntakeEnvelopeDoesNotPersistOrRelay(t *testing.T) {
 sends := 0
 q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
  sends++
  return nil
 })
 for _, recipient := range []string{"", "user@example.invalid\r\nDATA", "user\x00@example.invalid"} {
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
