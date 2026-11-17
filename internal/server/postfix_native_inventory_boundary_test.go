package server

import (
    "strings"
    "testing"
)

// These fixtures exercise the native postqueue -j parsing boundary, not an
// injected inventory provider. Invalid ownership evidence must never escape
// into queue correlation or the privileged release path.
func TestParseValidatedPostfixHold(t *testing.T) {
    const good = `{"queue_name":"hold","queue_id":"ABC123","sender":"sender@example.test","arrival_time":1700000000,"message_size":42,"recipients":[{"address":"one@example.test"}]}` + "\n"
    cases := []struct {
        name string
        input string
        accepted bool
    }{
        {"valid hold", good, true},
        {"empty queue", "", true},
        {"missing recipient", strings.Replace(good, "one@example.test", "", 1), false},
        {"recipient CR", strings.Replace(good, "one@example.test", "one@example.test\\rInjected", 1), false},
        {"recipient LF", strings.Replace(good, "one@example.test", "one@example.test\\nInjected", 1), false},
        {"recipient NUL", strings.Replace(good, "one@example.test", "one@example.test\\u0000", 1), false},
        {"duplicate queue", good + good, false},
        {"negative size", strings.Replace(good, "\"message_size\":42", "\"message_size\":-1", 1), false},
        {"missing arrival", strings.Replace(good, "\"arrival_time\":1700000000", "\"arrival_time\":0", 1), false},
        {"malformed JSON", "{not json}\n", false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := parseValidatedPostfixHold([]byte(tc.input))
            if tc.accepted && err != nil { t.Fatalf("valid native evidence rejected: %v", err) }
            if !tc.accepted && err == nil { t.Fatalf("unsafe native evidence accepted: %+v", got) }
            if err != nil && got != nil { t.Fatalf("partial evidence leaked on error: %+v", got) }
        })
    }
}
