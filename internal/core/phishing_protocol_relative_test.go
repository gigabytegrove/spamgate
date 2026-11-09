package core

import "testing"

// Protocol-relative links are navigable browser URLs. Both displayed claims
// and href destinations must be compared using their actual hostnames.
func TestPhishingProtocolRelativeClaims(t *testing.T) {
    cases := []struct {
        name, body string
        want int
    }{
        {"displayed relative different organization", `<a href="https://evil.example.net/login">//bank.example.com/login</a>`, 1},
        {"both relative different organization", `<a href="//evil.example.net/login">//bank.example.com/login</a>`, 1},
        {"displayed relative same organization", `<a href="https://login.example.com">//support.example.com</a>`, 0},
        {"relative matching destination", `<a href="//bank.example.com/login">//bank.example.com/login</a>`, 0},
        {"relative claim invisible formatting", `<a href="//evil.example.net/login">//bank.&#8203;example.com/login</a>`, 1},
        {"not a URL", `<a href="https://evil.example.net/login">/bank.example.com/login</a>`, 0},
        {"not a host", `<a href="https://evil.example.net/login">//</a>`, 0},
        {"no visible whitespace joining", "<a href=\"https://evil.example.net/login\">//bank. example.com/login</a>", 0},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            coverage := &mimeCoverage{}
            findings := phishingVisibleLinksWithCoverage(tc.body, coverage)
            if len(findings) != tc.want || coverage.Incomplete {
                t.Fatalf("findings=%v coverage=%+v want=%d", findings, coverage, tc.want)
            }
        })
    }
}

func TestPhishingProtocolRelativeMIME(t *testing.T) {
    body := `<a href="//evil.example.net/login">//bank.example.com/login</a>`
    findings, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
    if len(findings) != 1 || coverage.Incomplete {
        t.Fatalf("findings=%v coverage=%+v", findings, coverage)
    }
}
