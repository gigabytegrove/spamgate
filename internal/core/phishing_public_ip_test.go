package core

import (
    "strings"
    "testing"
)

func TestPhishingPublicIPLiteralDestinations(t *testing.T) {
    cases := []struct { name, href, shown string; want int }{
        {"public IPv4 mismatch", "https://8.8.8.8/login", "https://bank.example.com/login", 1},
        {"public IPv6 mismatch", "https://[2606:4700:4700::1111]/login", "https://bank.example.com/login", 1},
        {"loopback excluded", "https://127.0.0.1/login", "https://bank.example.com/login", 0},
        {"private IPv4 excluded", "https://192.168.10.20/login", "https://bank.example.com/login", 0},
        {"private IPv6 excluded", "https://[fd00::1]/login", "https://bank.example.com/login", 0},
        {"link local excluded", "https://169.254.1.2/login", "https://bank.example.com/login", 0},
        {"same domain remains benign", "https://bank.example.com/login", "https://bank.example.com/login", 0},
        {"different domain remains flagged", "https://evil.example.net/login", "https://bank.example.com/login", 1},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            raw := phishingFixture("text/html", "", "", `<a href="`+tc.href+`">`+tc.shown+`</a>`)
            got, coverage := detectPhishingLinksWithCoverage(raw)
            if coverage.Incomplete || len(got) != tc.want {
                t.Fatalf("findings=%v coverage=%+v want=%d", got, coverage, tc.want)
            }
            if tc.want == 1 && !strings.Contains(got[0], "navigates to") {
                t.Fatalf("missing destination evidence: %v", got)
            }
        })
    }
}

func TestPhishingDestinationHostClassification(t *testing.T) {
    for _, tc := range []struct{ host string; allowed bool }{
        {"8.8.8.8", true}, {"2606:4700:4700::1111", true},
        {"127.0.0.1", false}, {"10.0.0.1", false},
        {"fe80::1", false}, {"fd00::1", false},
        {"bank.example.com", true},
    } {
        if got := phishingPublicDestinationHost(tc.host); got != tc.allowed {
            t.Errorf("%q: got %v want %v", tc.host, got, tc.allowed)
        }
    }
}
