package server

import "testing"

func TestValidatePostfixReleaseInventory(t *testing.T) {
    valid := PostfixHeld{
        QueueID: "ABC123", Sender: "sender@example.test",
        Recipients: []string{"one@example.test", "two@example.test"},
        RecipientCount: 2, ArrivalTime: 1700000000, MessageSize: 42,
    }
    clone := func() PostfixHeld {
        v := valid
        v.Recipients = append([]string(nil), valid.Recipients...)
        return v
    }
    if err := validatePostfixReleaseInventory([]PostfixHeld{valid}); err != nil {
        t.Fatalf("valid inventory refused: %v", err)
    }
    if err := validatePostfixReleaseInventory(nil); err != nil {
        t.Fatalf("empty inventory should be safe to inspect: %v", err)
    }
    cases := []struct {
        name string
        mutate func(*PostfixHeld)
    }{
        {"sender control byte", func(v *PostfixHeld) { v.Sender = "sender@example.test\x1b[31m" }},
        {"sender padded", func(v *PostfixHeld) { v.Sender = " sender@example.test" }},
        {"sender overlong", func(v *PostfixHeld) { v.Sender = string(make([]byte, 1025)) }},
        {"recipient tab", func(v *PostfixHeld) { v.Recipients[0] = "one\t@example.test" }},
        {"recipient DEL", func(v *PostfixHeld) { v.Recipients[0] = "one\x7f@example.test" }},
        {"recipient escape", func(v *PostfixHeld) { v.Recipients[0] = "one\x1b[31m@example.test" }},
        {"recipient overlong", func(v *PostfixHeld) { v.Recipients[0] = string(make([]byte, 1025)) }},
        {"missing ID", func(v *PostfixHeld) { v.QueueID = "" }},
        {"ALL ID", func(v *PostfixHeld) { v.QueueID = "ALL" }},
        {"missing arrival", func(v *PostfixHeld) { v.ArrivalTime = 0 }},
        {"negative size", func(v *PostfixHeld) { v.MessageSize = -1 }},
        {"missing recipients", func(v *PostfixHeld) { v.Recipients = nil }},
        {"truncated recipients", func(v *PostfixHeld) { v.RecipientsTruncated = true }},
        {"recipient count mismatch", func(v *PostfixHeld) { v.RecipientCount = 3 }},
        {"empty recipient", func(v *PostfixHeld) { v.Recipients[0] = "" }},
        {"whitespace recipient", func(v *PostfixHeld) { v.Recipients[0] = "  " }},
        {"padded recipient", func(v *PostfixHeld) { v.Recipients[0] = " one@example.test " }},
        {"carriage return recipient", func(v *PostfixHeld) { v.Recipients[0] = "one@example.test\rInjected" }},
        {"newline recipient", func(v *PostfixHeld) { v.Recipients[0] = "one@example.test\nBcc:evil@example.test" }},
        {"NUL recipient", func(v *PostfixHeld) { v.Recipients[0] = "one@example.test\x00" }},
        {"overlong recipient evidence", func(v *PostfixHeld) { v.Recipients = make([]string, 51); for i := range v.Recipients { v.Recipients[i] = "one@example.test" }; v.RecipientCount = 51 }},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            item := clone()
            tc.mutate(&item)
            if err := validatePostfixReleaseInventory([]PostfixHeld{item}); err == nil {
                t.Fatal("unsafe inventory accepted")
            }
        })
    }
    t.Run("escaped backslash is not a control byte", func(t *testing.T) {
        item := clone()
        item.Recipients[0] = `one\\name@example.test`
        if err := validatePostfixReleaseInventory([]PostfixHeld{item}); err != nil {
            t.Fatalf("ordinary backslash must not be confused with CR/LF/NUL: %v", err)
        }
    })
    t.Run("inventory over entry limit", func(t *testing.T) {
        items := make([]PostfixHeld, 1001)
        for i := range items { items[i] = clone() }
        if err := validatePostfixReleaseInventory(items); err == nil { t.Fatal("oversized inventory accepted") }
    })
    t.Run("duplicate ID", func(t *testing.T) {
        second := clone()
        if err := validatePostfixReleaseInventory([]PostfixHeld{valid, second}); err == nil {
            t.Fatal("duplicate queue ID accepted")
        }
    })
}

func TestPostfixEnvelopeEvidenceDSNAndBackslash(t *testing.T) {
    for _, tc := range []struct {
        address string
        allowEmpty bool
        valid bool
    }{
        {"", true, true},
        {"", false, false},
        {`user\\name@example.test`, false, true},
        {"user@example.test", false, true},
        {"user@example.test\x01", false, false},
        {"user@example.test\x7f", false, false},
    } {
        if got := validPostfixEnvelopeEvidence(tc.address, tc.allowEmpty); got != tc.valid {
            t.Errorf("address %q allowEmpty=%v: got %v, want %v", tc.address, tc.allowEmpty, got, tc.valid)
        }
    }
}

func TestPostfixEnvelopeUnicodeIdentitySafety(t *testing.T) {
    cases := []struct {
        name string
        address string
        want bool
    }{
        {"SMTPUTF8 local part", "müller@example.test", true},
        {"internationalized domain", "user@例子.test", true},
        {"invalid UTF8", "user@example.test\xff", false},
        {"bidirectional override", "user\u202e@example.test", false},
        {"zero width joiner", "user\u200d@example.test", false},
        {"zero width nonjoiner", "user\u200c@example.test", false},
        {"zero width space", "user\u200b@example.test", false},
        {"unicode line separator", "user\u2028@example.test", false},
        {"unicode paragraph separator", "user\u2029@example.test", false},
        {"C1 control", "user\u0085@example.test", false},
        {"normal plus addressing", "user+tag@example.test", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            if got := validPostfixEnvelopeEvidence(tc.address, false); got != tc.want {
                t.Fatalf("got %v, want %v for %q", got, tc.want, tc.address)
            }
            item := PostfixHeld{
                QueueID: "ABC123", Sender: "sender@example.test",
                Recipients: []string{tc.address}, RecipientCount: 1,
                ArrivalTime: 1700000000, MessageSize: 42,
            }
            if err := validatePostfixReleaseInventory([]PostfixHeld{item}); (err == nil) != tc.want {
                t.Fatalf("inventory validation mismatch: %v", err)
            }
            item.Recipients[0] = "recipient@example.test"
            item.Sender = tc.address
            if err := validatePostfixReleaseInventory([]PostfixHeld{item}); (err == nil) != tc.want {
                t.Fatalf("sender validation mismatch: %v", err)
            }
        })
    }
}
