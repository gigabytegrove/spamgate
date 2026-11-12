package smtpprobe

import (
 "context"
 "reflect"
 "strings"
 "testing"
 "time"
)

func TestProbeExposesMalformedEHLOWithoutSubmittingMail(t *testing.T) {
 addr,commands:=server(t,"250-host.example\r\n250-AUTH bad/token\r\n250 BINARYMIME\r\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second})
 if err!=nil {t.Fatal(err)}
 want:=[]string{"MALFORMED_AUTH_MECHANISM","EMPTY_AUTH_ADVERTISEMENT","BINARYMIME_WITHOUT_CHUNKING"}
 if !reflect.DeepEqual(result.EHLOWarnings,want) {t.Fatalf("warnings=%q want=%q",result.EHLOWarnings,want)}
 if len(result.AuthMechanisms)!=0 || result.StartTLSAdvertised {t.Fatalf("untrustworthy capability promoted: %+v",result)}
 if len(result.PostTLSEHLOWarnings)!=0 {t.Fatalf("unexpected post TLS evidence: %+v",result)}
 for command:=range commands {
  if !strings.HasPrefix(command,"EHLO ") {t.Fatalf("unsafe command: %q",command)}
 }
}
