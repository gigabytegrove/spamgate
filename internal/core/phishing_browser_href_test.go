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
        {`https:\\evil.example.net\login`, "https://evil.example.net/login"},
        {`HTTPS:\\evil.example.net\login`, "HTTPS://evil.example.net/login"},
        {`\\evil.example.net\login`, "//evil.example.net/login"},
        {`javascript:alert(\\x)`, `javascript:alert(\\x)`},
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
        {"backslash HTTPS destination", `https:\\evil.example.net\login`, "https://bank.example.com/login", 1},
        {"backslash protocol-relative destination", `\\evil.example.net\login`, "https://bank.example.com/login", 1},
        {"matching backslash destination", `https:\\bank.example.com\login`, "https://bank.example.com/login", 0},
        {"same organization backslash destination", `https:\login.example.com\login`, "https://support.example.com", 0},
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

func TestPhishingBrowserC0AndProtocolRelativeAuthority(t *testing.T) {
    cases := []struct { name, href, want string }{
        {"leading C0", "\x01\x1fhttps://evil.example.net/login", "https://evil.example.net/login"},
        {"trailing C0", "https://evil.example.net/login\x1e\x00", "https://evil.example.net/login"},
        {"protocol relative triple", "///evil.example.net/login", "//evil.example.net/login"},
        {"protocol relative many", "//////evil.example.net/login", "//evil.example.net/login"},
        {"backslash relative", `\\\\\\evil.example.net\login`, "//evil.example.net/login"},
        {"ordinary path preserved", "https://evil.example.net/a///b", "https://evil.example.net/a///b"},
        {"visible internal space preserved", "https://evil.example.net/a b", "https://evil.example.net/a b"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            if got := phishingBrowserHref(tc.href); got != tc.want {
                t.Fatalf("normalized %q: got %q want %q", tc.href, got, tc.want)
            }
        })
    }
}

func TestPhishingBrowserProtocolRelativeMIME(t *testing.T) {
    for _, tc := range []struct { name, href, shown string; want int }{
        {"deceptive triple", "///evil.example.net/login", "https://bank.example.com/login", 1},
        {"deceptive many", "////evil.example.net/login", "https://bank.example.com/login", 1},
        {"matching", "///bank.example.com/login", "https://bank.example.com/login", 0},
        {"same organization", "///login.example.com", "https://support.example.com", 0},
        {"internal path separators", "https://bank.example.com/a///b", "https://bank.example.com/a///b", 0},
    } {
        t.Run(tc.name, func(t *testing.T) {
            raw := phishingFixture("text/html", "", "", `<a href="`+tc.href+`">`+tc.shown+`</a>`)
            findings, coverage := detectPhishingLinksWithCoverage(raw)
            if len(findings) != tc.want || coverage.Incomplete {
                t.Fatalf("findings=%v coverage=%+v want=%d", findings, coverage, tc.want)
            }
        })
    }
}
