package core

import "testing"

// A tiny but nonzero CSS opacity literal must not be rounded to zero by
// Go's float64 parser and then used to suppress a phishing finding.
func TestPhishingOpacityUnderflowDoesNotSuppressLinks(t *testing.T) {
 const mismatch = "<a href='https://evil.example.net'>https://bank.example.com</a>"
 for _, tc := range []struct {
  name, value string
  hidden bool
 }{
  {"positive underflow", "1e-999", false},
  {"negative underflow", "-1e-999", false},
  {"percentage underflow", "1e-999%", false},
  {"tiny decimal", "0.00000000000000000000000001", false},
  {"literal zero", "0e-999", true},
  {"negative zero", "-0.0", true},
  {"zero percentage", "0e-999%", true},
  {"regular opacity", "0.5", false},
 } {
  t.Run(tc.name, func(t *testing.T) {
   style := "opacity:" + tc.value
   if got := phishingInlineCSSHidden(style); got != tc.hidden {
    t.Fatalf("style %q hidden=%v want %v", style, got, tc.hidden)
   }
   coverage := &mimeCoverage{}
   findings := phishingVisibleLinksWithCoverage("<div style='"+style+"'>"+mismatch+"</div>", coverage)
   want := 1
   if tc.hidden { want = 0 }
   if len(findings) != want || coverage.Incomplete {
    t.Fatalf("style %q findings=%v coverage=%+v want %d", style, findings, coverage, want)
   }
  })
 }
}
