package core

import (
    "context"
    "fmt"
    "strings"
    "testing"
)

func TestPhishingVisibleLinkPSLOrganizationalBoundary(t *testing.T) {
    cases := []struct {
        name, shown, destination string
        mismatch bool
    }{
        {"same host", "bank.example.com", "bank.example.com", false},
        {"root to child", "example.com", "login.example.com", false},
        {"child to root", "login.example.com", "example.com", false},
        {"sibling hosts", "support.example.com", "login.example.com", false},
        {"nested sibling hosts", "help.eu.example.com", "login.us.example.com", false},
        {"co uk siblings", "www.example.co.uk", "auth.example.co.uk", false},
        {"co uk distinct owners", "example.co.uk", "other.co.uk", true},
        {"different tld", "example.com", "example.net", true},
        {"different registrable owners", "bank.example.com", "bank.other.com", true},
        {"github io tenants", "alice.github.io", "bob.github.io", true},
        {"github io tenant to public suffix", "alice.github.io", "github.io", true},
        {"github io public suffix to tenant", "github.io", "alice.github.io", true},
        {"github io same tenant subhosts", "www.alice.github.io", "login.alice.github.io", false},
        {"pages dev tenants", "alice.pages.dev", "bob.pages.dev", true},
        {"pages dev same tenant", "www.alice.pages.dev", "login.alice.pages.dev", false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            html := fmt.Sprintf("<a href=\"https://%s/signin\">https://%s/signin</a>", tc.destination, tc.shown)
            got := phishingVisibleLinks(html)
            if (len(got) == 1) != tc.mismatch {
                t.Fatalf("visible URL claim mismatch=%v, want %v (findings=%v)", len(got) == 1, tc.mismatch, got)
            }
            if len(got) > 1 {
                t.Fatalf("duplicate phishing findings: %v", got)
            }
        })
    }
}

func TestPhishingPSLBoundaryMIMEAndClassifierOptIn(t *testing.T) {
    cases := []struct{ name, shown, destination string; want bool }{
        {"legitimate sibling", "support.example.com", "login.example.com", false},
        {"different github tenants", "alice.github.io", "bob.github.io", true},
        {"different co uk owners", "example.co.uk", "other.co.uk", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            store, err := Open(t.TempDir())
            if err != nil { t.Fatal(err) }
            scanner := &Scanner{Store: store, Resolver: stubDNS{}}
            body := fmt.Sprintf("<a href=\"https://%s/login\">https://%s/login</a>", tc.destination, tc.shown)
            raw := []byte("From: sender@example.org\r\nTo: recipient@example.net\r\n" +
                "Date: Sun, 01 Nov 2026 15:00:00 +0000\r\n" +
                "Message-ID: <psl-" + strings.ReplaceAll(tc.name, " ", "-") + "@example.org>\r\n" +
                "MIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n" + body)
            scan := func() bool {
                t.Helper()
                msg, err := scanner.Scan(context.Background(), Input{
                    Raw: raw, Sender: "sender@example.org",
                    Recipients: []string{"recipient@example.net"}, Connector: "milter",
                })
                if err != nil { t.Fatal(err) }
                for _, finding := range msg.Findings {
                    if finding.Symbol == "PHISHING_VISIBLE_LINK" { return true }
                }
                return false
            }
            if scan() { t.Fatal("disabled phishing check produced a scored finding") }
            if err := store.UpdateConfig(func(c *Config) error {
                c.Settings.PhishingLinks = true
                return nil
            }); err != nil { t.Fatal(err) }
            if got := scan(); got != tc.want {
                t.Fatalf("enabled phishing check scored=%v want=%v", got, tc.want)
            }
        })
    }
}
