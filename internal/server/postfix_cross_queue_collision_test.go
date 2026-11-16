package server

import (
 "fmt"
 "strings"
 "testing"
)

func TestPostfixCrossQueueIDCollisionFailsClosed(t *testing.T) {
 for _, tc := range []struct{name, queue string; firstHold bool; collision bool}{
  {"active then hold", "active", false, true},
  {"deferred then hold", "deferred", false, true},
  {"hold then active", "active", true, true},
  {"distinct active", "active", false, false},
 } {
  t.Run(tc.name,func(t *testing.T){
   firstID, secondID := "A1B2", "A1B2"
   if !tc.collision {firstID = "C3D4"}
   first := fmt.Sprintf("{\"queue_name\":%q,\"queue_id\":%q}\n",tc.queue,firstID)
   hold := holdInventoryLine(secondID,"alice@example.org")
   if tc.firstHold {first,hold=hold,first}
   got,err:=parsePostfixHold([]byte(first+hold))
   if tc.collision {
    if err==nil || !strings.Contains(err.Error(),"duplicate") {t.Fatalf("cross-queue collision accepted: %v %v",got,err)}
   } else if err!=nil || len(got)!=1 {t.Fatalf("distinct queues rejected: %v %v",got,err)}
  })
 }
}

func TestPostfixNonHoldQueueIDValidation(t *testing.T) {
 for _, id := range []string{"../bad","-H"} {
  input:=fmt.Sprintf("{\"queue_name\":\"active\",\"queue_id\":%q}\n",id)
  if got,err:=parsePostfixHold([]byte(input));err==nil {t.Fatalf("invalid non-HOLD ID %q accepted: %+v",id,got)}
 }
}
