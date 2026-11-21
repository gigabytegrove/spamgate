package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestMultidimensionalCLIGates(t *testing.T) {
 dir:=t.TempDir()
 before:=filepath.Join(dir,"before.json")
 after:=filepath.Join(dir,"after.json")
 write:=func(path string, queued,delivering,dead,pending int) {
  t.Helper()
  published:=queued+delivering+dead
  report:=map[string]any{
   "gate_passed":true,"gate_failures":[]string{},
   "examined":published+pending,"published":published,"pending":pending,
   "states":map[string]int{"queued":queued,"delivering":delivering,"dead":dead},
   "findings":[]string{},"truncated":false,
  }
  b,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
 }
 write(before,1,1,1,1)
 write(after,2,3,2,3)
 args:=[]string{"-before",before,"-after",after,
  "-max-queue-growth","1","-max-dead-growth","1",
  "-max-delivering-growth","1","-max-pending-growth","1","-max-dead-count","1"}
 var out,errs bytes.Buffer
 if code:=run(args,&out,&errs);code!=1{t.Fatalf("want gate failure exit 1, got %d: %s",code,errs.String())}
 var result struct {
  GatePassed bool `json:"gate_passed"`
  GateFailures []string `json:"gate_failures"`
 }
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil{t.Fatal(err)}
 if result.GatePassed||len(result.GateFailures)!=3{t.Fatalf("unexpected decision: %+v",result)}
 args[len(args)-1]="2"
 args[len(args)-3]="2"
 args[len(args)-5]="2"
 out.Reset();errs.Reset()
 if code:=run(args,&out,&errs);code!=0{t.Fatalf("inclusive limits should pass: %d %s %s",code,out.String(),errs.String())}
 args[len(args)-1]="-2"
 out.Reset();errs.Reset()
 if code:=run(args,&out,&errs);code!=2||!strings.Contains(errs.String(),"max-dead-count"){t.Fatalf("invalid limit not rejected: %d %s",code,errs.String())}
}
