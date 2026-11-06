package transport

import (
 "context"
 "encoding/json"
 "os"
 "strings"
 "testing"
 "unicode"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestUnicodeEnvelopeControlsRejected(t *testing.T) {
 controls := []struct{name string; value string}{
  {"next line", "\u0085"},
  {"C1 escape", "\u009b"},
  {"line separator", "\u2028"},
  {"paragraph separator", "\u2029"},
  {"arabic letter mark", "\u061c"},
  {"left to right mark", "\u200e"},
  {"right to left mark", "\u200f"},
  {"embedding", "\u202a"},
  {"override", "\u202e"},
  {"pop direction", "\u202c"},
  {"isolate", "\u2066"},
  {"pop isolate", "\u2069"},
  {"zero width space", "\u200b"},
  {"zero width non joiner", "\u200c"},
  {"zero width joiner", "\u200d"},
  {"word joiner", "\u2060"},
  {"byte order mark", "\ufeff"},
  {"soft hyphen", "\u00ad"},
  {"interlinear annotation anchor", "\ufff9"},
 }
 for _, tc := range controls {
  t.Run(tc.name,func(t *testing.T) {
   address := "a"+tc.value+"@example.invalid"
   if err:=validateIntakeEnvelope(address, []string{"b@example.invalid"});err==nil {
    t.Fatal("unsafe sender accepted")
   }
   if err:=validateIntakeEnvelope("", []string{address});err==nil {
    t.Fatal("unsafe recipient accepted")
   }
   if validSMTPEnvelopeText(address) {t.Fatal("unsafe text accepted")}
  })
 }
 for _, address := range []string{"séndér@example.invalid", "récepteur@example.invalid", "a\u0301@example.invalid"} {
  if err:=validateIntakeEnvelope("",[]string{address});err!=nil {
   t.Fatalf("valid SMTPUTF8 rejected: %v",err)
  }
 }
}

func TestUnicodeEnvelopeRejectedWithoutSpoolOrRelay(t *testing.T) {
 sends:=0
 q,_,_:=newRecoveryQueue(t,func(context.Context,core.Message,[]byte)error{sends++;return nil})
 for i, value := range []string{"\u0085","\u2028","\u202e","\u2066","\u200b","\u200c","\u200d","\u2060","\ufeff","\u00ad"} {
  for _, sender := range []bool{false,true} {
   id:=core.ID()
   msg:=core.Message{ID:id,Sender:"sender@example.invalid",Recipients:[]string{"user@example.invalid"},Action:"accept"}
   if sender {msg.Sender="a"+value+"@example.invalid"} else {msg.Recipients=[]string{"a"+value+"@example.invalid"}}
   if err:=q.Enqueue(msg,[]byte("Subject: test\r\n\r\noriginal"));err==nil {
    t.Fatalf("unsafe envelope accepted case %d sender=%t",i,sender)
   }
   if _,err:=os.Stat(q.path(id));!os.IsNotExist(err) {t.Fatalf("rejected envelope persisted: %v",err)}
  }
 }
 if err:=q.ProcessDue(context.Background());err!=nil {t.Fatal(err)}
 if sends!=0 {t.Fatalf("rejected mail relayed %d times",sends)}
}

func TestCanonicalLegacyUnicodeControlsRejected(t *testing.T) {
 for _, value := range []string{"\u0085","\u2028","\u202e","\u2066"} {
  for _, sender := range []bool{false,true} {
   address:="a"+value+"@example.invalid"
   senderValue:="sender@example.invalid"
   recipientValue:="user@example.invalid"
   if sender {senderValue=address} else {recipientValue=address}
   // json.Marshal escapes the Unicode separators; validation must operate
   // on decoded identity rather than scanning literal JSON bytes.
   raw:=map[string]any{
    "id":strings.Repeat("a",32),"sender":senderValue,
    "recipients":[]string{recipientValue},"raw":"SGVsbG8=",
    "state":"queued","size":5,"attempts":0,
    "created":"2026-11-05T18:00:00Z",
    "updated":"2026-11-05T18:00:00Z",
    "next_attempt":"2026-11-05T18:00:00Z",
   }
   encoded,err:=json.Marshal(raw)
   if err!=nil {t.Fatal(err)}
   if err:=validateCanonicalSpoolRecordJSON(encoded);err==nil {
    t.Fatal("unsafe legacy Unicode envelope accepted")
   }
  }
 }
}

// TestEveryUnicodeFormatControlRejected prevents a newly assigned Cf code
// point from silently bypassing the intake and legacy-recovery boundary.
func TestEveryUnicodeFormatControlRejected(t *testing.T) {
 for r := rune(0); r <= 0x10ffff; r++ {
  if !unicode.Is(unicode.Cf, r) { continue }
  address := "user" + string(r) + "@example.invalid"
  if validSMTPEnvelopeText(address) {
   t.Fatalf("Unicode Cf U+%04X accepted", r)
  }
  if err := validateIntakeEnvelope("", []string{address}); err == nil {
   t.Fatalf("Unicode Cf U+%04X recipient accepted", r)
  }
  if err := validateIntakeEnvelope(address, []string{"user@example.invalid"}); err == nil {
   t.Fatalf("Unicode Cf U+%04X sender accepted", r)
  }
 }
}

func TestUnicodeEnvelopeSafeMarksAndEmptyReversePath(t *testing.T) {
 for _, addr := range []string{
  "a\u0301@example.invalid", "é@example.invalid",
  "用户@例子.invalid", "مستخدم@example.invalid",
 } {
  if err := validateIntakeEnvelope("", []string{addr}); err != nil {
   t.Fatalf("valid internationalized recipient rejected: %v", err)
  }
 }
}
