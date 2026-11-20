package smtpprobe

import (
 "strings"
 "testing"
)

func TestEnhancedStatusCanonicalAndBounded(t *testing.T) {
 cases := []struct {name string; code int; lines []string; want string}{
  {"standard",550,[]string{"5.7.1 Policy"},"5.7.1"},
  {"bare",421,[]string{"4.3.2"},"4.3.2"},
  {"multi",550,[]string{"5.7.1 First", "5.7.1 Second"},"5.7.1"},
  {"tab",550,[]string{"5.7.1\tPolicy"},"5.7.1"},
  {"leading zero subject",550,[]string{"5.07.1 Policy"},""},
  {"leading zero detail",550,[]string{"5.7.001 Policy"},""},
  {"unicode space",550,[]string{"5.7.1\u00a0Policy"},""},
  {"line feed",550,[]string{"5.7.1\n5.7.1"},""},
  {"carriage return",550,[]string{"5.7.1\rInjected"},""},
  {"nul",550,[]string{"5.7.1\x00Injected"},""},
  {"class mismatch",450,[]string{"5.7.1"},""},
  {"bad code",350,[]string{"3.7.1"},""},
  {"too many lines",550,func() []string {a:=make([]string,101);for i:=range a {a[i]="5.7.1"};return a}(),""},
  {"line too long",550,[]string{"5.7.1 "+strings.Repeat("a",507)},""},
  {"mixed",550,[]string{"5.7.1", "5.7.2"},""},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){if got:=observedEnhancedStatus(tc.code,tc.lines);got!=tc.want {t.Fatalf("got %q want %q",got,tc.want)}}) }
}

func TestEnhancedStatusFindingRejectsNoncanonicalResult(t *testing.T) {
 r:=Result{StartTLSReplyCode:454,StartTLSEnhancedCode:"4.07.0"}
 if got:=enhancedReplyFindings(r);len(got)!=0 {t.Fatalf("invalid status emitted finding: %+v",got)}
 r.StartTLSEnhancedCode="4.7.0"
 if got:=enhancedReplyFindings(r);len(got)!=1 || got[0].Code!="STARTTLS_ENHANCED_REPLY" {t.Fatalf("missing valid evidence: %+v",got)}
}
