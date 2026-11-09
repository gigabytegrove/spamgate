package core

import (
    "strings"
    "testing"
)

func TestPhishingSurplusAuthoritySlashNormalization(t *testing.T) {
    cases := []struct{ input, want string }{
        {"https:////evil.example.net/login", "https://evil.example.net/login"},
        {"HTTPS://///evil.example.net/login", "HTTPS://evil.example.net/login"},
        {"http:///evil.example.net", "http://evil.example.net"},
        {"https:\\\\\\\\evil.example.net/login", "https://evil.example.net/login"},
        {"https://evil.example.net/a///b", "https://evil.example.net/a///b"},
        {"https:/relative", "https:/relative"},
        {"https:relative", "https:relative"},
        {"mailto:////evil.example.net", "mailto:////evil.example.net"},
        {"javascript:////evil.example.net", "javascript:////evil.example.net"},
    }
    for _, tc := range cases {
        if got := phishingBrowserHref(tc.input); got != tc.want {
            t.Errorf("normalize %q = %q, want %q", tc.input, got, tc.want)
        }
    }
}

func TestPhishingSurplusAuthoritySlashDetection(t *testing.T) {
    cases := []struct{ name, href, text string; want int }{
        {"surplus HTTPS slashes", "https:////evil.example.net/login", "https://bank.example.com/login", 1},
        {"surplus HTTP slashes", "http:////evil.example.net/login", "https://bank.example.com/login", 1},
        {"matching authority", "https:////bank.example.com/login", "https://bank.example.com/login", 0},
        {"same organization", "https:////login.example.com/login", "https://support.example.com", 0},
        {"not an HTTP scheme", "mailto:////evil.example.net", "https://bank.example.com", 0},
        {"no visible URL claim", "https:////evil.example.net/login", "Sign in", 0},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            html := `<a href="` + tc.href + `">` + tc.text + `</a>`
            if got := phishingVisibleLinks(html); len(got) != tc.want {
                t.Fatalf("findings=%v want=%d", got, tc.want)
            }
        })
    }
}

func TestPhishingSurplusAuthoritySlashMIME(t *testing.T) {
    html := `<a href="https:////evil.example.net/login">https://bank.example.com/login</a>`
    findings, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", html))
    if coverage.Incomplete || len(findings) != 1 || !strings.Contains(findings[0], "evil.example.net") {
        t.Fatalf("findings=%v coverage=%+v", findings, coverage)
    }
}
