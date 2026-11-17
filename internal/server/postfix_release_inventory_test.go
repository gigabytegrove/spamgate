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
        {"missing ID", func(v *PostfixHeld) { v.QueueID = "" }},
        {"ALL ID", func(v *PostfixHeld) { v.QueueID = "ALL" }},
        {"missing arrival", func(v *PostfixHeld) { v.ArrivalTime = 0 }},
        {"negative size", func(v *PostfixHeld) { v.MessageSize = -1 }},
        {"missing recipients", func(v *PostfixHeld) { v.Recipients = nil }},
        {"truncated recipients", func(v *PostfixHeld) { v.RecipientsTruncated = true }},
        {"recipient count mismatch", func(v *PostfixHeld) { v.RecipientCount = 3 }},
        {"empty recipient", func(v *PostfixHeld) { v.Recipients[0] = "" }},
        {"whitespace recipient", func(v *PostfixHeld) { v.Recipients[0] = "  " }},
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
    t.Run("duplicate ID", func(t *testing.T) {
        second := clone()
        if err := validatePostfixReleaseInventory([]PostfixHeld{valid, second}); err == nil {
            t.Fatal("duplicate queue ID accepted")
        }
    })
}
