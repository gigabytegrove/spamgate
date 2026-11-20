package smtpprobe

import (
 "strings"
 "testing"
)

func TestEnhancedReplyRejectsUnsafeControlBytes(t *testing.T) {
 for _, b := range []byte{0, 1, 2, 7, 8, 10, 11, 12, 13, 27, 31, 127} {
  for _, line := range []string{"5.7.1" + string([]byte{b}) + " blocked", "5.7.1 blocked" + string([]byte{b})} {
   if got := observedEnhancedStatus(550, []string{line}); got != "" {
    t.Fatalf("accepted control byte %d in %q: %q", b, line, got)
   }
  }
 }
}

func TestEnhancedReplyAllowsTabDelimiterButNotUnicodeWhitespace(t *testing.T) {
 if got := observedEnhancedStatus(550, []string{"5.7.1\tblocked"}); got != "5.7.1" {
  t.Fatalf("tab delimiter rejected: %q", got)
 }
 for _, line := range []string{"5.7.1\u00a0blocked", "5.7.1\u2003blocked", "5.7.1\u2028blocked"} {
  if got := observedEnhancedStatus(550, []string{line}); got != "" {
   t.Fatalf("accepted non-ASCII delimiter: %q", got)
  }
 }
}

func TestEnhancedReplyManualResultControlByteCannotBecomeFinding(t *testing.T) {
 for _, stage := range []string{"greeting", "ehlo", "starttls", "posttls"} {
  r := Result{}
  switch stage {
  case "greeting": r.BannerCode = 550; r.BannerEnhancedCode = "5.7.1 blocked\x1b"
  case "ehlo": r.EHLOCode = 550; r.EHLOEnhancedCode = "5.7.1 blocked\x1b"
  case "starttls": r.StartTLSReplyCode = 550; r.StartTLSEnhancedCode = "5.7.1 blocked\x1b"
  case "posttls": r.PostTLSEHLOCode = 550; r.PostTLSEHLOEnhancedCode = "5.7.1 blocked\x1b"
  }
  for _, f := range enhancedReplyFindings(r) {
   if strings.Contains(f.Code, "ENHANCED_REPLY") {
    t.Fatalf("%s emitted untrusted finding: %+v", stage, f)
   }
  }
 }
}

func TestEnhancedReplyBoundsAndCanonicalClasses(t *testing.T) {
 tests := []struct { code int; lines []string; want string }{
  {550, []string{"5.7.1 rejected"}, "5.7.1"},
  {450, []string{"4.7.1 delayed"}, "4.7.1"},
  {550, []string{"4.7.1 mismatch"}, ""},
  {550, []string{"5.07.1 noncanonical"}, ""},
  {550, []string{"5.7.1 first", "5.7.1 second"}, "5.7.1"},
  {550, []string{"5.7.1 first", "5.7.2 second"}, ""},
  {550, []string{strings.Repeat("x", 513)}, ""},
 }
 for _, tc := range tests {
  if got := observedEnhancedStatus(tc.code, tc.lines); got != tc.want {
   t.Fatalf("code=%d lines=%q got=%q want=%q", tc.code, tc.lines, got, tc.want)
  }
 }
}
