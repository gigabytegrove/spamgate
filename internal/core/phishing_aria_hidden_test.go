package core

import "testing"

// aria-hidden removes descendants from the accessibility tree, but does not
// visually hide them or disable pointer navigation. An attacker can set it on
// a visible link; the phishing classifier must still inspect that link.
func TestPhishingAriaHiddenDoesNotSuppressRenderedLinks(t *testing.T) {
 const mismatch = `<a href="https://evil.example.net/login">https://bank.example.com/login</a>`
 cases := []struct { name, body string; want int }{
  {"aria true on anchor", `<a aria-hidden="true" href="https://evil.example.net/login">https://bank.example.com/login</a>`, 1},
  {"aria true on parent", `<section aria-hidden="true">`+mismatch+`</section>`, 1},
  {"aria mixed case", `<div ARIA-HIDDEN="TRUE">`+mismatch+`</div>`, 1},
  {"aria encoded true", `<div aria-hidden="tr&#117;e">`+mismatch+`</div>`, 1},
  {"aria true and sibling", `<div aria-hidden="true">`+mismatch+`</div>`+mismatch, 2},
  {"aria false", `<div aria-hidden="false">`+mismatch+`</div>`, 1},
  {"actual hidden dominates aria", `<div hidden aria-hidden="false">`+mismatch+`</div>`, 0},
  {"display none dominates aria", `<div aria-hidden="false" style="display:none">`+mismatch+`</div>`, 0},
  {"inert remains noninteractive", `<div inert aria-hidden="false">`+mismatch+`</div>`, 0},
  {"hidden child and visible sibling", `<div aria-hidden="true"><span hidden>`+mismatch+`</span>`+mismatch+`</div>`, 1},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   coverage := &mimeCoverage{}
   got := phishingVisibleLinksWithCoverage(tc.body, coverage)
   if coverage.Incomplete || len(got) != tc.want {
    t.Fatalf("got=%v coverage=%+v want=%d", got, coverage, tc.want)
   }
  })
 }
}

func TestPhishingAriaHiddenMIMEIntegration(t *testing.T) {
 const body = `<div aria-hidden="true"><a href="https://evil.example.net/login">https://bank.example.com/login</a></div>`
 found, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
 if coverage.Incomplete || len(found) == 0 {
  t.Fatalf("visually rendered link disappeared in MIME classifier: %v %+v", found, coverage)
 }
}
