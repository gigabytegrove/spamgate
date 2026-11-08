package core

import (
    "strings"
    "testing"
)

func TestPhishingVisibleURLAcrossInlineElements(t *testing.T) {
    cases := []struct {
        name string
        html string
        want int
    }{
        {"split scheme", `<a href="https://evil.example.net"><span>https:</span><span>//bank.example.com</span></a>`, 1},
        {"split hostname", `<a href="https://evil.example.net">https://bank.<b>example</b>.com</a>`, 1},
        {"split with formatting", `<a href="https://evil.example.net"><strong>https://</strong><em>bank.example.com</em></a>`, 1},
        {"legitimate split sibling", `<a href="https://login.example.com">https://<span>support.example.com</span></a>`, 0},
        {"explicit space", `<a href="https://evil.example.net">https://bank. <span>example.com</span></a>`, 0},
        {"line break", `<a href="https://evil.example.net">https://bank.<br>example.com</a>`, 0},
        {"block boundary", `<a href="https://evil.example.net">https://bank.<div>example.com</div></a>`, 0},
        {"unrelated text", `<a href="https://evil.example.net"><span>Review your account</span></a>`, 0},
        {"hidden fragment", `<a href="https://evil.example.net">https://bank.<span hidden>example</span>example.com</a>`, 1},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            coverage := &mimeCoverage{}
            got := phishingVisibleLinksWithCoverage(tc.html, coverage)
            if len(got) != tc.want || coverage.Incomplete {
                t.Fatalf("findings=%v coverage=%+v want=%d", got, coverage, tc.want)
            }
        })
    }
}

func TestPhishingInlineSplitMIMEIntegration(t *testing.T) {
    body := `<a href="https://evil.example.net"><span>https://bank.</span><span>example.com</span></a>`
    got, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
    if len(got) != 1 || coverage.Incomplete {
        t.Fatalf("MIME findings=%v coverage=%+v", got, coverage)
    }
}

func TestPhishingInlineSplitBoundedAnchorText(t *testing.T) {
    body := `<a href="https://evil.example.net">` + strings.Repeat("<span>x</span>", 4200) + `</a>`
    coverage := &mimeCoverage{}
    got := phishingVisibleLinksWithCoverage(body, coverage)
    if len(got) != 0 || !coverage.Incomplete {
        t.Fatalf("oversized inline text should be skipped with coverage evidence: %v %+v", got, coverage)
    }
}
