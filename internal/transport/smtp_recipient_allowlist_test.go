package transport

import (
    "net"
    "testing"
)

// The allowlist is an authorization boundary, not just a convenience filter.
// Unicode simple case folding can authorize domains that were never configured.
func TestSMTPRecipientAllowlistUsesASCIIDNSCase(t *testing.T) {
    gateway := &SMTP{Domains: []string{"k.example", "example.org"}}
    cases := []struct {
        address string
        allowed bool
    }{
        {"Alice@EXAMPLE.ORG", true},
        {"alice@example.org", true},
        {"alice@K.EXAMPLE", true},
        {"alice@k.example", true},
        {"alice@K.example", false},
        {"alice@Ｋ.example", false},
        {"alice@k.example.evil", false},
        {"alice@evil-example.org", false},
        {"alice@example.org.", false},
        {"alice@example.org@evil.invalid", false},
        {"alice", false},
    }
    for _, tc := range cases {
        if got := gateway.allowedRecipient(tc.address); got != tc.allowed {
            t.Errorf("allowedRecipient(%q) = %v, want %v", tc.address, got, tc.allowed)
        }
    }
}

func TestSMTPRecipientAllowlistDoesNotChangeEnvelopeIdentity(t *testing.T) {
    gateway := &SMTP{
        Domains: []string{"example.org"},
        CIDRs: []*net.IPNet{},
    }
    recipients := []string{"Alice@EXAMPLE.ORG"}
    if !gateway.allowedRecipient("Alice@example.org") {
        t.Fatal("ASCII domain case mismatch")
    }
    var accepted bool
    recipients, accepted = acceptSMTPRecipient(recipients, "Alice@example.org", 1)
    if !accepted || len(recipients) != 1 || recipients[0] != "Alice@EXAMPLE.ORG" {
        t.Fatalf("accepted envelope was rewritten: %v %q", accepted, recipients)
    }
    if gateway.allowedRecipient("Alice@K.example") {
        t.Fatal("Unicode domain was authorized")
    }
}
