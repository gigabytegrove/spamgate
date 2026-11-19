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
        {"::ffff:192.168.1.7", false},
        {"::ffff:127.0.0.1", false},
        {"::ffff:169.254.1.2", false},
        {"::ffff:8.8.8.8", true},
        {"fe80::1%eth0", false},
        {"ff02::1", false},
        {"::", false},
        {"0.1.2.3", false},
        {"100.64.0.1", false},
        {"100.127.255.254", false},
        {"192.0.2.1", false},
        {"198.18.0.1", false},
        {"198.51.100.10", false},
        {"203.0.113.42", false},
        {"240.1.2.3", false},
        {"2001:db8::1", false},
        {"::ffff:203.0.113.8", false},
        {"100.128.0.1", true},
        {"198.20.0.1", true},
        {"bank.example.com", true},
    } {
        if got := phishingPublicDestinationHost(tc.host); got != tc.allowed {
            t.Errorf("%q: got %v want %v", tc.host, got, tc.allowed)
        }
    }
}

func TestPhishingSpecialPurposeDestinationsDoNotScore(t *testing.T) {
    for _, host := range []string{
        "192.0.2.1", "198.51.100.2", "203.0.113.3",
        "100.64.0.1", "198.18.1.2", "[2001:db8::1]",
        "[::ffff:203.0.113.9]",
    } {
        t.Run(host, func(t *testing.T) {
            raw := phishingFixture("text/html", "", "",
                `<a href="https://`+host+`/login">https://bank.example.com/login</a>`)
            got, coverage := detectPhishingLinksWithCoverage(raw)
            if coverage.Incomplete || len(got) != 0 {
                t.Fatalf("special-use destination %s: findings=%v coverage=%+v", host, got, coverage)
            }
        })
    }
}

func TestPhishingAdditionalSpecialUseBoundaries(t *testing.T) {
    cases := []struct{ host string; want bool }{
        {"192.88.99.1", false},
        {"192.88.98.255", true},
        {"192.88.100.1", true},
        {"2001:2::1", false},
        {"2001:2:0:ffff::1", false},
        {"2001:2:1::1", true},
        {"2001:10::1", false},
        {"2001:1f::1", false},
        {"2001:20::1", false},
        {"2001:2f::1", false},
        {"2001:30::1", true},
        {"2606:4700:4700::1111", true},
    }
    for _, tc := range cases {
        t.Run(tc.host, func(t *testing.T) {
            if got := phishingPublicDestinationHost(tc.host); got != tc.want {
                t.Fatalf("host=%s got=%v want=%v", tc.host, got, tc.want)
            }
        })
    }
}

func TestPhishingAdditionalSpecialUseHTML(t *testing.T) {
    for _, host := range []string{"192.88.99.1", "[2001:2::1]", "[2001:10::1]", "[2001:20::1]"} {
        t.Run(host, func(t *testing.T) {
            raw := phishingFixture("text/html", "", "", `<a href="https://`+host+`/login">https://bank.example.com/login</a>`)
            findings, coverage := detectPhishingLinksWithCoverage(raw)
            if coverage.Incomplete || len(findings) != 0 {
                t.Fatalf("host=%s findings=%v coverage=%+v", host, findings, coverage)
            }
        })
    }
}
