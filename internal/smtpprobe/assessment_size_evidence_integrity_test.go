package smtpprobe

import "testing"

// An ambiguous SIZE extension cannot support a trustworthy limit comparison.
// The warning itself is reported by capabilityEvidenceFindings.
func TestAssessSizeDriftRequiresUnambiguousEvidence(t *testing.T) {
 cases := []struct {
  name string
  before, after bool
  beforeWarning, afterWarning string
  want bool
 }{
  {"valid numeric limits", true, true, "", "", true},
  {"malformed initial SIZE", true, true, "duplicate SIZE", "", false},
  {"malformed post TLS SIZE", true, true, "", "invalid SIZE", false},
  {"both ambiguous", true, true, "duplicate SIZE", "invalid SIZE", false},
  {"initial SIZE absent", false, true, "", "", false},
  {"post TLS SIZE absent", true, false, "", "", false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   r := Result{
    EHLOCode: 250, StartTLSAdvertised: true, StartTLSVerified: true,
    PostTLSEHLOCode: 250,
    SizeAdvertised: tc.before, PostTLSSizeAdvertised: tc.after,
    SizeLimitKnown: true, PostTLSSizeLimitKnown: true,
    SizeLimitBytes: 1024, PostTLSSizeLimitBytes: 2048,
    SizeWarning: tc.beforeWarning, PostTLSSizeWarning: tc.afterWarning,
   }
   codes := findingCodes(Assess(r))
   if codes["SIZE_LIMIT_CHANGED_AFTER_TLS"] != tc.want {
    t.Fatalf("SIZE drift finding=%v, want %v; findings=%+v", codes["SIZE_LIMIT_CHANGED_AFTER_TLS"], tc.want, Assess(r))
   }
  })
 }
}

func TestAssessSizeDriftRequiresVerifiedPostTLSCapabilities(t *testing.T) {
 for _, tc := range []struct{name string; verified bool; code int}{
  {"unverified TLS", false, 250},
  {"rejected post TLS EHLO", true, 550},
  {"missing post TLS EHLO", true, 0},
 } {
  t.Run(tc.name, func(t *testing.T) {
   r := Result{
    EHLOCode: 250, StartTLSAdvertised: true, StartTLSVerified: tc.verified,
    PostTLSEHLOCode: tc.code,
    SizeAdvertised: true, PostTLSSizeAdvertised: true,
    SizeLimitKnown: true, PostTLSSizeLimitKnown: true,
    SizeLimitBytes: 1024, PostTLSSizeLimitBytes: 2048,
   }
   if findingCodes(Assess(r))["SIZE_LIMIT_CHANGED_AFTER_TLS"] {
    t.Fatalf("reported SIZE drift without verified post-TLS evidence: %+v", Assess(r))
   }
  })
 }
}
