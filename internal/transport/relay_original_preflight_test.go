package transport

import (
    "context"
    "errors"
    "net"
    "strings"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestRelayInvalidOriginalFailsBeforeConnecting(t *testing.T) {
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil { t.Fatal(err) }
    address := listener.Addr().String()
    listener.Close() // Any attempted dial now fails with a network error.
    relay := &Relay{Address: address, TLSMode: "required"}
    valid := core.Message{Sender: "sender@example.org", Recipients: []string{"recipient@example.org"}}
    cases := []struct {
        name string
        message core.Message
        raw string
        invalid bool
    }{
        {"missing recipient", core.Message{Sender: valid.Sender}, "Subject: ok\r\n\r\nbody\r\n", true},
        {"injected recipient", core.Message{Sender: valid.Sender, Recipients: []string{"victim@example.org> SIZE=0"}}, "Subject: ok\r\n\r\nbody\r\n", true},
        {"bare carriage return", valid, "Subject: ok\rbroken\r\n\r\nbody\r\n", true},
        {"nul byte", valid, "Subject: ok\r\n\r\nbody\x00\r\n", true},
        {"invalid utf8 header", valid, "Subject: \xff\r\n\r\nbody\r\n", true},
        {"empty original", valid, "", true},
        {"valid original has transient connection error", valid, "Subject: ok\r\n\r\nbody\r\n", false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            ctx, cancel := context.WithTimeout(context.Background(), time.Second)
            defer cancel()
            err := relay.Send(ctx, tc.message, []byte(tc.raw))
            if err == nil { t.Fatal("closed relay unexpectedly accepted mail") }
            var invalid *invalidRelayOriginalError
            if errors.As(err, &invalid) != tc.invalid {
                t.Fatalf("invalid classification = %t, want %t: %v", errors.As(err, &invalid), tc.invalid, err)
            }
            if isPermanentRelayFailure(err) != tc.invalid {
                t.Fatalf("permanent classification mismatch: %v", err)
            }
            if tc.invalid && strings.Contains(err.Error(), "connection refused") {
                t.Fatalf("network was consulted before invalid original was rejected: %v", err)
            }
        })
    }
}
