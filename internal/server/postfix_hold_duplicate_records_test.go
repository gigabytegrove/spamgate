package server

import (
 "fmt"
 "strings"
 "testing"
)

func TestPostfixHoldDuplicateInventoryIDsFailClosed(t *testing.T) {
 for _, tc := range []struct{name, first, second string; duplicate bool}{
  {"identical","AB12","AB12",true},
  {"conflicting case","AB12","ab12",false},
  {"different","AB12","CD34",false},
 } {
  t.Run(tc.name,func(t *testing.T){
   input:=holdInventoryLine(tc.first,"alice@example.org")+holdInventoryLine(tc.second,"bob@example.org")
   records,err:=parsePostfixHold([]byte(input))
   if tc.duplicate {
    if err==nil || !strings.Contains(err.Error(),"duplicate") {t.Fatalf("duplicate ID accepted: %v %v",records,err)}
   } else if err!=nil || len(records)!=2 {t.Fatalf("valid distinct IDs rejected: %v %v",records,err)}
  })
 }
}

func TestPostfixHoldInventoryCapacityFailClosed(t *testing.T) {
 var b strings.Builder
 for i:=0;i<1000;i++ {b.WriteString(holdInventoryLine(fmt.Sprintf("%08X",i),"alice@example.org"))}
 records,err:=parsePostfixHold([]byte(b.String()))
 if err!=nil || len(records)!=1000 {t.Fatalf("1000 entries: %d %v",len(records),err)}
 b.WriteString(holdInventoryLine("FFFFFFFF","alice@example.org"))
 if _,err:=parsePostfixHold([]byte(b.String()));err==nil {t.Fatal("over-limit HOLD inventory accepted")}
}

func holdInventoryLine(id,recipient string) string {
 return fmt.Sprintf("{\"queue_name\":\"hold\",\"queue_id\":%q,\"sender\":\"sender@example.org\",\"arrival_time\":1793100000,\"message_size\":100,\"recipients\":[{\"address\":%q}]}\n",id,recipient)
}
