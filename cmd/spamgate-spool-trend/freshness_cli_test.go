package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestFreshnessCLIRejectsInvalidDurationsBeforeReadingEvidence(t *testing.T) {
 for _,arg:=range []string{"-max-snapshot-age=-1s","-max-snapshot-gap=-1s"} {
  t.Run(arg,func(t *testing.T){
   var out,err bytes.Buffer
   code:=run([]string{"-before","before.json","-after","after.json",arg},&out,&err)
   if code!=2 || !strings.Contains(err.String(),"nonnegative") {t.Fatalf("code=%d stderr=%q",code,err.String())}
   if out.Len()!=0 {t.Fatalf("unexpected stdout %q",out.String())}
  })
 }
}
