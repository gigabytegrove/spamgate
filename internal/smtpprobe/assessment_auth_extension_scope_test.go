package smtpprobe

import "testing"

// Duplicate unrelated extensions must not invalidate otherwise trustworthy AUTH.
func TestCapabilityWarningsSeparateAUTHFromOtherDuplicates(t *testing.T) {
 cases := []struct {
  name string
  lines []string
  wantAUTH bool
  wantDuplicate bool
 }{
  {"duplicate PIPELINING", []string{"mail.example","AUTH PLAIN","PIPELINING","PIPELINING"},false,true},
  {"duplicate SIZE", []string{"mail.example","AUTH PLAIN","SIZE 1024","SIZE 2048"},false,true},
  {"duplicate AUTH", []string{"mail.example","AUTH PLAIN","AUTH LOGIN"},true,true},
  {"mixed AUTH syntax", []string{"mail.example","AUTH PLAIN","AUTH=LOGIN"},true,true},
  {"clean", []string{"mail.example","AUTH PLAIN","PIPELINING"},false,false},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   warnings:=capabilityWarnings(tc.lines)
   has:=func(code string) bool {for _,w:=range warnings {if w==code{return true}};return false}
   if has("DUPLICATE_AUTH_EXTENSION")!=tc.wantAUTH {t.Fatalf("AUTH duplicate warning: %v",warnings)}
   if has("DUPLICATE_EXTENSION")!=tc.wantDuplicate {t.Fatalf("generic duplicate warning: %v",warnings)}
   if ambiguousAUTH(warnings)!=tc.wantAUTH {t.Fatalf("AUTH ambiguity: %v",warnings)}
  })
 }
}

func TestAssessUnrelatedDuplicateDoesNotSuppressAUTHChanges(t *testing.T) {
 r:=Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,
  AuthMechanisms:[]string{"PLAIN"},PostTLSAuthMechanisms:[]string{"LOGIN"},
  EHLOWarnings:[]string{"DUPLICATE_EXTENSION"}}
 codes:=findingCodes(Assess(r))
 if !codes["AUTH_MECHANISMS_CHANGED_AFTER_TLS"] || !codes["AUTH_MECHANISMS_ADDED_AFTER_TLS"] {
  t.Fatalf("unrelated duplicate suppressed observed AUTH changes: %v",codes)
 }
 if codes["AUTH_EVIDENCE_UNTRUSTWORTHY"] {t.Fatalf("unrelated duplicate tainted AUTH: %v",codes)}
}
