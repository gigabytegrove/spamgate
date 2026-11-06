package transport

import (
 "context"
 "os"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestEnvelopeMetadataBounds(t *testing.T) {
 valid := strings.Repeat("a", maxEnvelopeAddressBytes)
 if err := validateIntakeEnvelope(valid, []string{valid}); err != nil { t.Fatalf("boundary address rejected: %v", err) }
 if err := validateIntakeEnvelope("", []string{"récepteur@example.invalid"}); err != nil { t.Fatalf("SMTPUTF8 rejected: %v", err) }
 if err := validateIntakeEnvelope(valid+"a", []string{"user@example.invalid"}); err == nil { t.Fatal("oversized sender accepted") }
 if err := validateIntakeEnvelope("", []string{valid+"a"}); err == nil { t.Fatal("oversized recipient accepted") }
 recipients := make([]string, 129)
 for i := range recipients { recipients[i] = valid }
 if err := validateIntakeEnvelope("", recipients[:128]); err != nil { t.Fatalf("aggregate boundary rejected: %v", err) }
 if err := validateIntakeEnvelope("", recipients); err == nil { t.Fatal("oversized aggregate accepted") }
 if err := validateIntakeEnvelope("", []string{"user\n@example.invalid"}); err == nil { t.Fatal("control byte accepted") }
 if err := validateIntakeEnvelope("", []string{"a\u200b@example.invalid"}); err == nil { t.Fatal("format control accepted") }
}

func TestOversizedEnvelopeNeverPersistsOrRelays(t *testing.T) {
 sends := 0
 q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
  sends++
  return nil
 })
 recipients := make([]string, 129)
 for i := range recipients { recipients[i] = strings.Repeat("a", maxEnvelopeAddressBytes) }
 cases := []struct {
  sender string
  recipients []string
 }{
  {strings.Repeat("s", maxEnvelopeAddressBytes+1), []string{"user@example.invalid"}},
  {"", []string{strings.Repeat("r", maxEnvelopeAddressBytes+1)}},
  {"", recipients},
 }
 for _, tc := range cases {
  id := core.ID()
  msg := core.Message{ID:id, Sender:tc.sender, Recipients:tc.recipients, Action:"accept"}
  if err := q.Enqueue(msg, []byte("Subject: test\r\n\r\nbody")); err == nil { t.Fatal("oversized envelope admitted") }
  if _, err := os.Stat(q.path(id)); !os.IsNotExist(err) { t.Fatalf("rejected envelope persisted: %v", err) }
 }
 if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if sends != 0 { t.Fatalf("rejected mail relayed %d times", sends) }
}
