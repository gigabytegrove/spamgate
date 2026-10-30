package main

import (
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/transport"
)

func TestSMTPIntakeRefusesUnspooledStartup(t *testing.T) {
 if err := requireDurableSMTP(nil,nil);err!=nil{t.Fatalf("Milter-only startup blocked: %v",err)}
 in:=&transport.SMTP{}
 if err:=requireDurableSMTP(in,nil);err==nil||!strings.Contains(err.Error(),"durable delivery queue"){
  t.Fatalf("unsafe direct SMTP mode permitted: %v",err)
 }
 queue:=&transport.DeliveryQueue{}
 if err:=requireDurableSMTP(in,queue);err==nil{t.Fatal("SMTP intake allowed unbound queue")}
 in.Queue=queue
 if err:=requireDurableSMTP(in,queue);err!=nil{t.Fatalf("durable mode refused: %v",err)}
}
