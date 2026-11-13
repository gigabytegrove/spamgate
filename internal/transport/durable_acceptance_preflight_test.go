package transport

import (
    "testing"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// These are the exact bytes and envelope checked before SMTP 250 and again
// when the durable worker replays the original.
func TestDurableAcceptanceRelayPreflight(t *testing.T) {
    valid := core.Message{
        Sender: "sender@example.org",
        Recipients: []string{"recipient@example.net"},
    }
    cases := []struct {
        name string
        message core.Message
        raw string
        reject bool
    }{
        {"ordinary original", valid, "Subject: accepted\r\n\r\nbody\r\n", false},
        {"tagged original", valid, "X-SpamGate-Result: tag\r\nX-SpamGate-Score: 2.00\r\nX-SpamGate-ID: abc123\r\nSubject: accepted\r\n\r\nbody\r\n", false},
        {"missing recipients", core.Message{Sender: valid.Sender}, "Subject: accepted\r\n\r\nbody\r\n", true},
        {"invalid recipient envelope", core.Message{Sender: valid.Sender, Recipients: []string{"recipient@example.net> SIZE=0"}}, "Subject: accepted\r\n\r\nbody\r\n", true},
        {"injected tag header", valid, "X-SpamGate-ID: abc\rInjected: yes\r\nSubject: accepted\r\n\r\nbody\r\n", true},
        {"invalid header encoding", valid, "Subject: \xff\r\n\r\nbody\r\n", true},
        {"embedded nul", valid, "Subject: accepted\r\n\r\nbody\x00\r\n", true},
        {"empty original", valid, "", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            err := validateRelayOriginal(tc.message, []byte(tc.raw))
            if (err != nil) != tc.reject {
                t.Fatalf("preflight error = %v, reject = %t", err, tc.reject)
            }
        })
    }
}
