package smtpprobe

import "testing"

func TestBinaryMIMEConsistencyEvidence(t *testing.T) {
 cases := []struct{name string; lines []string; code string}{
  {"both present",[]string{"server","CHUNKING","BINARYMIME"},""},
  {"missing chunking",[]string{"server","BINARYMIME"},"EHLO_BINARYMIME_WITHOUT_CHUNKING"},
  {"duplicate chunking",[]string{"server","BINARYMIME","CHUNKING","CHUNKING"},"EHLO_BINARYMIME_CHUNKING_AMBIGUOUS"},
  {"malformed chunking",[]string{"server","BINARYMIME","CHUNKING extra"},"EHLO_BINARYMIME_CHUNKING_AMBIGUOUS"},
  {"no binarymime",[]string{"server","CHUNKING"},""},
 }
 for _, tc := range cases {t.Run(tc.name,func(t *testing.T){
  f:=binaryMIMEConsistencyFindings(inspectExtensions(tc.lines),"EHLO")
  if tc.code=="" {if len(f)!=0 {t.Fatalf("unexpected findings: %+v",f)};return}
  if len(f)!=1 || f[0].Code!=tc.code {t.Fatalf("got %+v want %s",f,tc.code)}
 })}
}
func TestBinaryMIMEAssessmentBeforeAndAfterTLS(t *testing.T) {
 r:=Result{BannerCode:220,EHLOCode:250,Extensions:inspectExtensions([]string{"server","CHUNKING","BINARYMIME"}),StartTLSVerified:true,PostTLSEHLOCode:250,PostTLSExtensions:inspectExtensions([]string{"server","BINARYMIME"})}
 for _,f:=range Assess(r) {if f.Code=="POST_TLS_EHLO_BINARYMIME_WITHOUT_CHUNKING" {return}}
 t.Fatal("missing post-TLS protocol inconsistency")
}
