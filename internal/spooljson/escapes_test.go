package spooljson

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestUnicodeEscapeIntegrity(t *testing.T) {
    tests := []struct {
        name string
        json string
        reject bool
    }{
        {"plain ASCII", `{"state":"queued"}`, false},
        {"literal UTF8", `{"subject":"☃ 😄"}`, false},
        {"valid surrogate pair", `{"subject":"\uD83D\uDE04"}`, false},
        {"adjacent valid pairs", `{"subject":"\ud83d\ude04\uD83D\uDE03"}`, false},
        {"non-surrogate escape", `{"subject":"\u017F"}`, false},
        {"escaped slash u literal", `{"subject":"\\ud800"}`, false},
        {"escaped quote then valid pair", `{"subject":"\"\uD83D\uDE04"}`, false},
        {"high surrogate alone", `{"subject":"\ud800"}`, true},
        {"low surrogate alone", `{"subject":"\udc00"}`, true},
        {"high then normal code unit", `{"subject":"\ud800\u0041"}`, true},
        {"two high surrogates", `{"subject":"\ud800\ud801"}`, true},
        {"high then literal rune", `{"subject":"\ud800😄"}`, true},
        {"high then intervening character", `{"subject":"\ud800x\udc00"}`, true},
        {"high then escaped backslash", `{"subject":"\ud800\\udc00"}`, true},
        {"invalid escape hex", `{"subject":"\uD80Z"}`, true},
        {"truncated escape", `{"subject":"\uD80"}`, true},
        {"truncated pair", `{"subject":"\uD800\uDC0"}`, true},
        {"nested surrogate key", `{"scan":{"\ud800":"x"}}`, true},
        {"nested valid surrogate key", `{"scan":{"\uD83D\uDE04":"x"}}`, false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            err := validateUnicodeEscapes([]byte(tc.json))
            if tc.reject != (err != nil) {
                t.Fatalf("reject=%v, err=%v", tc.reject, err)
            }
            if !tc.reject && !json.Valid([]byte(tc.json)) {
                t.Fatal("valid fixture is not JSON")
            }
            if err != nil && strings.Contains(err.Error(), "subject") {
                t.Fatal("error leaked JSON content")
            }
        })
    }
}

func TestUnicodeEscapesLinearBoundedScan(t *testing.T) {
    input := []byte(`{"subject":"` + strings.Repeat(`\u0041`, 300000) + `"}`)
    if err := validateUnicodeEscapes(input); err != nil {
        t.Fatal(err)
    }
}

func FuzzUnicodeEscapeValidation(f *testing.F) {
    for _, seed := range []string{`{"a":"\ud800"}`, `{"a":"\uD83D\uDE04"}`, `{"a":"\\ud800"}`, `{"a":"\ud800\udc00"}`} {
        f.Add(seed)
    }
    f.Fuzz(func(t *testing.T, s string) {
        _ = validateUnicodeEscapes([]byte(s))
    })
}
