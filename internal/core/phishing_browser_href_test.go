package core

import (
    "strings"
    "testing"
)

func TestPhishingBrowserHrefPreprocessing(t *testing.T) {
    cases := []struct{ input, want string }{
        {"https://evil.example.net", "https://evil.example.net"},
        {"ht\ttps://evil.example.net", "https://evil.example.net"},
        {"https://ev\nil.example.net", "https://evil.example.net"},
        {"https://evil.example.\rnet", "https://evil.example.net"},
        {" \t\nhttps://evil.example.net/login\r\n ", "https://evil.example.net/login"},
        {"https://evil.example.net/a b", "https://evil.example.net/a b"},
    }
    for _, tc := range cases {
        if got := phishingBrowserHref(tc.input); got != tc.want {
            t.Errorf("href %q normalized to %q, want %q", tc.input, got, tc.want)
        }
    }
}

func TestPhishingBrowserNormalizedDestinations(t *testing.T) {
    cases := []struct{ name, href, displayed string; want int }{
        {"tab in destination host", "https://ev\til.example.net/login", "https://bank.example.com/login", 1},
        {"LF in destination scheme", "ht\ntps://evil.example.net/login", "https://bank.example.com/login", 1},
        {"CR in destination host", "https://evil.example.\rnet/login", "https://bank.example.com/login", 1},
        {"matching after normalization", "https://bank.\nexample.com/login", "https://bank.example.com/login", 0},
        {"same organization after normalization", "https://login.\texample.com", "https://support.example.com", 0},
        {"visible whitespace not joined", "https://evil.example.net", "https://bank. example.com", 0},
        {"non-http URL excluded", "javascript:alert(1)", "https://bank.example.com", 0},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            body := `<a href="` + tc.href + `">` + tc.displayed + `</a>`
            findings := phishingVisibleLinks(body)
            if len(findings) != tc.want {
                t.Fatalf("findings=%v want=%d", findings, tc.want)
            }
        })
    }
}

func TestPhishingBrowserNormalizedDestinationMIME(t *testing.T) {
    body := `<a href="https://ev` + "\t" + `il.example.net/login">https://bank.example.com/login</a>`
    findings, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
    if len(findings) != 1 || coverage.Incomplete || !strings.Contains(findings[0], "evil.example.net") {
        t.Fatalf("findings=%v coverage=%+v", findings, coverage)
    }
}
