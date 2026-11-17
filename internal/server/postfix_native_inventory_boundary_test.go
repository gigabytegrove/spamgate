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
        {"non-hold valid identity", good + `{"queue_name":"active","queue_id":"DEF456"}` + "\n", true},
        {"non-hold missing ID", good + `{"queue_name":"active","sender":"other@example.test"}` + "\n", false},
        {"non-hold null ID", good + `{"queue_name":"deferred","queue_id":null}` + "\n", false},
        {"non-hold invalid ID", good + `{"queue_name":"active","queue_id":"ALL"}` + "\n", false},
        {"non-hold missing queue name", good + `{"queue_id":"DEF456"}` + "\n", false},
        {"unknown queue class", good + `{"queue_name":"future","queue_id":"DEF456"}` + "\n", false},
        {"case spoofed HOLD", good + `{"queue_name":"Hold","queue_id":"DEF456"}` + "\n", false},
        {"padded HOLD", good + `{"queue_name":"hold ","queue_id":"DEF456"}` + "\n", false},
        {"maildrop identity", good + `{"queue_name":"maildrop","queue_id":"DEF456"}` + "\n", true},
        {"incoming identity", good + `{"queue_name":"incoming","queue_id":"DEF456"}` + "\n", true},
        {"non-hold duplicate ID", good + `{"queue_name":"active","queue_id":"ABC123"}` + "\n", false},
        {"non-hold distinct IDs", good + `{"queue_name":"deferred","queue_id":"DEF456"}` + "\n" + `{"queue_name":"active","queue_id":"GHI789"}` + "\n", true},
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
