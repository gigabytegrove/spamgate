package main

import (
 "bytes"
 "reflect"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

func TestDeliveryAgeFailures(t *testing.T) {
 report:=spoolaudit.Report{OldestQueuedSeconds:3600,OldestDeliveringSeconds:7200}
 tests:=[]struct{
  name string
  queued,delivering int64
  want []string
 }{
  {"disabled",-1,-1,nil},
  {"inclusive",3600,7200,nil},
  {"both",3599,7199,[]string{"queued_age_seconds=3600 exceeds max-queued-age-seconds=3599","delivering_age_seconds=7200 exceeds max-delivering-age-seconds=7199"}},
  {"queued_only",0,-1,[]string{"queued_age_seconds=3600 exceeds max-queued-age-seconds=0"}},
  {"delivering_only",-1,0,[]string{"delivering_age_seconds=7200 exceeds max-delivering-age-seconds=0"}},
 }
 for _,tt:=range tests {
  t.Run(tt.name,func(t *testing.T){
   got:=deliveryAgeFailures(report,tt.queued,tt.delivering)
   if !reflect.DeepEqual(got,tt.want){t.Fatalf("got %v, want %v",got,tt.want)}
  })
 }
}

func TestDeliveryAgeFlagsRejectInvalidLimits(t *testing.T) {
 for _,arg:=range []string{"-max-queued-age-seconds=-2","-max-delivering-age-seconds=-2"} {
  var out,err bytes.Buffer
  if got:=run([]string{arg},&out,&err);got!=2 {t.Errorf("%s: exit %d, want 2; stderr %s",arg,got,err.String())}
 }
}
