package spooljson

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestFoldJSONKeyMatchesEncodingJSONSimpleFold(t *testing.T) {
    cases := [][2]string{
        {"state", "ſtate"},
        {"State", "ſTATE"},
        {"scan", "ſcan"},
        {"sender", "ſender"},
        {"K", "K"},
        {"Σ", "ς"},
        {"σ", "ς"},
        {"state", "status"},
        {"α", "β"},
    }
    for _, pair := range cases {
        got := foldJSONKey(pair[0]) == foldJSONKey(pair[1])
        want := strings.EqualFold(pair[0], pair[1])
        if got != want {
            t.Errorf("simple fold %q vs %q = %t, want %t", pair[0], pair[1], got, want)
        }
    }
}

func TestEncodingJSONAcceptsUnicodeConflictingStateKeys(t *testing.T) {
    for _, payload := range []string{
        `{"state":"dead","ſtate":"queued"}`,
        `{"ſtate":"dead","state":"queued"}`,
        `{"state":"dead","\\u017ftate":"queued"}`,
    } {
        var decoded struct { State string `json:"state"` }
        if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
            t.Fatal(err)
        }
        if decoded.State != "queued" {
            t.Fatalf("fixture failed to reproduce last-value-wins state: %q", decoded.State)
        }
        if err := Validate([]byte(payload)); err == nil || !strings.Contains(err.Error(), "duplicate") {
            t.Fatalf("ambiguous durable state was accepted: %v", err)
        }
    }
}
