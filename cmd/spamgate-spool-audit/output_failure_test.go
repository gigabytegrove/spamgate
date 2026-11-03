package main

import (
 "bytes"
 "errors"
 "io"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

type failOutput struct {
 remaining int
 err error
}
func (w *failOutput) Write(p []byte) (int,error) {
 if w.remaining <= 0 { return 0,w.err }
 n:=len(p)
 if n>w.remaining { n=w.remaining }
 w.remaining-=n
 if n<len(p) { return n,w.err }
 return n,nil
}
var _ io.Writer = (*failOutput)(nil)

func TestAuditOutputFailureIsFatal(t *testing.T) {
 dir:=filepath.Join(t.TempDir(),"delivery-queue")
 if err:=os.Mkdir(dir,0700);err!=nil {t.Fatal(err)}
 for _,jsonMode:=range []bool{false,true} {
  args:=[]string{"-dir",dir}
  if jsonMode {args=append(args,"-json")}
  for _,limit:=range []int{0,4} {
   var stderr bytes.Buffer
   out:=&failOutput{remaining:limit,err:errors.New("output unavailable")}
   if got:=run(args,out,&stderr);got!=2 {
    t.Errorf("json=%t limit=%d exit=%d; want 2",jsonMode,limit,got)
   }
   if !strings.Contains(stderr.String(),"write spool audit:") {
    t.Errorf("json=%t limit=%d missing output failure: %s",jsonMode,limit,stderr.String())
   }
  }
 }
}

func TestAuditFindingsOutputFailureTakesPrecedence(t *testing.T) {
 dir:=filepath.Join(t.TempDir(),"delivery-queue")
 if err:=os.Mkdir(dir,0700);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,".pending-incomplete"),[]byte("bad"),0600);err!=nil {t.Fatal(err)}
 var stderr bytes.Buffer
 if got:=run([]string{"-dir",dir},&failOutput{err:errors.New("broken pipe")},&stderr);got!=2 {
  t.Fatalf("exit=%d; want output error 2, stderr=%s",got,stderr.String())
 }
 var out bytes.Buffer
 stderr.Reset()
 if got:=run([]string{"-dir",dir},&out,&stderr);got!=1 {
  t.Fatalf("exit=%d; want findings 1",got)
 }
 if !strings.Contains(out.String(),"unreadable_record") {t.Fatal("missing finding")}
}
