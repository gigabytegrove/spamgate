package transport

import (
    "fmt"
    "testing"
)

func TestAcceptSMTPRecipientAtCapacity(t *testing.T) {
    var recipients []string
    for i := 0; i < 100; i++ {
        address := fmt.Sprintf("user%03d@example.org", i)
        var ok bool
        recipients, ok = acceptSMTPRecipient(recipients, address, 100)
        if !ok { t.Fatalf("recipient %d rejected before capacity", i) }
    }
    original := append([]string(nil), recipients...)
    var ok bool
    recipients, ok = acceptSMTPRecipient(recipients, "user000@example.org", 100)
    if !ok || len(recipients) != 100 {
        t.Fatalf("duplicate at capacity rejected or counted: ok=%v count=%d", ok, len(recipients))
    }
    recipients, ok = acceptSMTPRecipient(recipients, "new@example.org", 100)
    if ok || len(recipients) != 100 {
        t.Fatalf("new mailbox accepted at capacity: ok=%v count=%d", ok, len(recipients))
    }
    for i := range original {
        if recipients[i] != original[i] { t.Fatalf("envelope mutated at index %d", i) }
    }
    recipients, ok = acceptSMTPRecipient(recipients, "User000@example.org", 100)
    if ok { t.Fatal("case-distinct local part must consume a new slot") }
}

func TestAcceptSMTPRecipientIdentityAndBoundary(t *testing.T) {
    var recipients []string
    for _, address := range []string{"a@example.org", "a+tag@example.org", "A@example.org"} {
        var ok bool
        recipients, ok = acceptSMTPRecipient(recipients, address, 3)
        if !ok { t.Fatalf("distinct address %q rejected", address) }
    }
    recipients, ok := acceptSMTPRecipient(recipients, "a+tag@example.org", 3)
    if !ok || len(recipients) != 3 { t.Fatalf("repeat rejected: %v %q", ok, recipients) }
    recipients, ok = acceptSMTPRecipient(recipients, "b@example.org", 3)
    if ok || len(recipients) != 3 { t.Fatalf("overflow accepted: %v %q", ok, recipients) }
    recipients, ok = acceptSMTPRecipient(recipients, "c@example.org", 0)
    if ok || len(recipients) != 3 { t.Fatal("zero capacity must reject new recipient") }
}
