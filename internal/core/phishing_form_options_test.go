package core

import (
 "strings"
 "testing"
)

// Browsers do not expose clickable anchor links inside select/datalist option
// trees. Treating markup in those controls as a rendered link can produce a
// high-confidence phishing false positive for inert fallback/template text.
func TestPhishingFormOptionMarkupIsNotClickable(t *testing.T) {
 const mismatch = `<a href="https://evil.example.net/login">https://bank.example.com/login</a>`
 cases := []struct {name, body string; want int}{
  {"select", "<select><option>"+mismatch+"</option></select>", 0},
  {"datalist", "<datalist><option>"+mismatch+"</option></datalist>", 0},
  {"option", "<option>"+mismatch+"</option>", 0},
  {"optgroup", "<optgroup>"+mismatch+"</optgroup>", 0},
  {"visible sibling", "<select><option>"+mismatch+"</option></select>"+mismatch, 1},
  {"datalist visible sibling", "<datalist><option>"+mismatch+"</option></datalist>"+mismatch, 1},
  {"select with nested option", "<select><optgroup><option>"+mismatch+"</option></optgroup></select>", 0},
  {"visible outside option", mismatch+"<select><option>"+mismatch+"</option></select>", 1},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   coverage := &mimeCoverage{}
   got := phishingVisibleLinksWithCoverage(tc.body, coverage)
   if len(got) != tc.want || coverage.Incomplete {
    t.Fatalf("findings=%v coverage=%+v want=%d", got, coverage, tc.want)
   }
  })
 }
}

func TestPhishingFormOptionMIMEIntegration(t *testing.T) {
 const mismatch = `<a href="https://evil.example.net/login">https://bank.example.com/login</a>`
 for _, body := range []string{
  "<select><option>"+mismatch+"</option></select>",
  "<datalist><option>"+mismatch+"</option></datalist>",
 } {
  got, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
  if len(got) != 0 || coverage.Incomplete {
   t.Fatalf("non-clickable form option was scored: %v %+v", got, coverage)
  }
  if strings.Contains(strings.Join(got, " "), "Visible link claims") {
   t.Fatalf("inert form option produced visible-link claim: %v", got)
  }
 }
}
