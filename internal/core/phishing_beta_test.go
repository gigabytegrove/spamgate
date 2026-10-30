package core

import (
    "context"
    "strings"
    "testing"
)

func TestBetaPhishingAnchorAttributesAndFalsePositives(t *testing.T) {
    cases := []struct {
        name string
        html string
        want int
    }{
        {"real mismatch", `<a href="https://malicious.example.net/login">https://bank.example.com/login</a>`, 1},
        {"scheme-relative mismatch", `<a href="//malicious.example.net/login">https://bank.example.com/login</a>`, 1},
        {"html-entity href", `<a href="https:&#x2f;&#x2f;malicious.example.net/login">https://bank.example.com</a>`, 1},
        {"data href is not a link", `<a data-href="https://malicious.example.net" href="https://bank.example.com">https://bank.example.com</a>`, 0},
        {"quoted title is not a link", `<a title="text href='https://malicious.example.net'" href="https://bank.example.com">https://bank.example.com</a>`, 0},
        {"quoted greater-than", `<a title="1 > 0 href='https://malicious.example.net'" href="https://bank.example.com">https://bank.example.com</a>`, 0},
        {"commented anchor", `<!-- <a href="https://malicious.example.net">https://bank.example.com</a> -->`, 0},
        {"duplicate href first wins", `<a href="https://bank.example.com" href="https://malicious.example.net">https://bank.example.com</a>`, 0},
        {"legitimate subdomain", `<a href="https://login.bank.example.com">https://bank.example.com</a>`, 0},
        {"button text no URL claim", `<a href="https://malicious.example.net">View your shipment</a>`, 0},
        {"nested display markup", `<a class="cta" href="https://malicious.example.net"><span>https://bank.example.com</span></a>`, 1},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := phishingVisibleLinks(tc.html)
            if len(got) != tc.want {
                t.Fatalf("expected %d mismatches, got %+v", tc.want, got)
            }
        })
    }
}

func TestBetaPhishingOptInAndDecodedMIME(t *testing.T) {
    st, err := Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    scanner := &Scanner{Store: st, Resolver: stubDNS{}}
    raw := []byte("From: sender@example.com\r\nTo: user@example.org\r\nDate: Fri, 30 Oct 2026 01:00:00 +0000\r\nMessage-ID: <phish-test@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n<a href=\"//malicious.example.net\">https://bank.example.com</a>")
    scan := func() Message {
        t.Helper()
        m, err := scanner.Scan(context.Background(), Input{Raw: raw, Sender: "sender@example.com", Recipients: []string{"user@example.org"}, Connector: "milter"})
        if err != nil { t.Fatal(err) }
        return m
    }
    hasFinding := func(m Message) bool {
        for _, f := range m.Findings { if f.Symbol == "PHISHING_VISIBLE_LINK" { return true } }
        return false
    }
    if hasFinding(scan()) { t.Fatal("phishing inspection must remain opt-in") }
    if err := st.UpdateConfig(func(c *Config) error { c.Settings.PhishingLinks = true; return nil }); err != nil { t.Fatal(err) }
    if !hasFinding(scan()) { t.Fatal("enabled phishing inspection did not score scheme-relative mismatch") }
    commented := strings.Replace(string(raw), "<a href=", "<!-- <a href=", 1)
    commented = strings.Replace(commented, "</a>", "</a> -->", 1)
    if got := detectPhishingLinks([]byte(commented)); len(got) != 0 {
        t.Fatalf("commented link should not count: %+v", got)
    }
}
