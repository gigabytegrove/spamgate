package transport

import (
    "reflect"
    "testing"
)

func TestSMTPRecipientDomainCaseIdentity(t *testing.T) {
    cases := []struct{ a, b string; same bool }{
        {"Alice@EXAMPLE.ORG", "Alice@example.org", true},
        {"Alice@example.org", "alice@example.org", false},
        {"Alice+tag@example.org", "Alice@example.org", false},
        {"Alice+tag@EXAMPLE.ORG", "Alice+tag@example.org", true},
        {"Alice@one.example", "Alice@two.example", false},
        {"bad", "BAD", false},
        {"bad", "bad", true},
        {"@example.org", "@EXAMPLE.ORG", false},
    }
    for _, tc := range cases {
        if got := sameSMTPRecipient(tc.a, tc.b); got != tc.same {
            t.Errorf("sameSMTPRecipient(%q,%q)=%v; want %v", tc.a, tc.b, got, tc.same)
        }
        if got := sameSMTPRecipient(tc.b, tc.a); got != tc.same {
            t.Errorf("symmetry (%q,%q)=%v; want %v", tc.b, tc.a, got, tc.same)
        }
    }
}

func TestSMTPRecipientDomainCaseAtCapacity(t *testing.T) {
    original := []string{"Alice@EXAMPLE.ORG", "alice@example.org"}
    accepted := append([]string(nil), original...)
    var ok bool
    accepted, ok = acceptSMTPRecipient(accepted, "Alice@example.org", 2)
    if !ok || !reflect.DeepEqual(accepted, original) {
        t.Fatalf("case-only domain duplicate at capacity: accepted=%v addresses=%q", ok, accepted)
    }
    accepted, ok = acceptSMTPRecipient(accepted, "Alice+tag@example.org", 2)
    if ok || !reflect.DeepEqual(accepted, original) {
        t.Fatalf("new plus address accepted at capacity: accepted=%v addresses=%q", ok, accepted)
    }
}

func TestUniqueSMTPRecipientsKeepsFirstWireAddress(t *testing.T) {
    input := []string{
        "Alice@EXAMPLE.ORG", "Alice@example.org",
        "alice@example.org", "Alice+tag@Example.Org",
        "Alice+tag@example.org", "Alice@elsewhere.org",
    }
    want := []string{
        "Alice@EXAMPLE.ORG", "alice@example.org",
        "Alice+tag@Example.Org", "Alice@elsewhere.org",
    }
    got := uniqueSMTPRecipients(input)
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("got %q; want %q", got, want)
    }
    if len(input) != 6 { t.Fatal("source envelope mutated") }
}
