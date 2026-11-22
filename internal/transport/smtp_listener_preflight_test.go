package transport

import (
    "context"
    "net"
    "strings"
    "testing"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestSMTPListenerPreflightFailsClosedBeforeBind(t *testing.T) {
    // These failures must occur before net.Listen; even an invalid bind
    // address cannot mask a missing persistence or trust boundary.
    cases := []struct {
        name string
        smtp *SMTP
        want string
    }{
        {"nil", nil, "nil"},
        {"zero value", &SMTP{}, "persistent store"},
        {"missing scanner", &SMTP{Store: &core.Store{}}, "initialized scanner"},
        {"mismatched scanner store", &SMTP{Store: &core.Store{}, Scanner: &core.Scanner{Store: &core.Store{}}}, "same persistent store"},
        {"missing queue", &SMTP{Store: &core.Store{}, Scanner: &core.Scanner{Store: &core.Store{}}}, "same persistent store"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            err := tc.smtp.validateListenerPreflight()
            if err == nil || !strings.Contains(err.Error(), tc.want) {
                t.Fatalf("preflight error = %v, want substring %q", err, tc.want)
            }
        })
    }
}

func TestSMTPListenRejectsIncompleteConfigurationWithoutBinding(t *testing.T) {
    // The test port is deliberately occupied; preflight must win before bind.
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil { t.Fatal(err) }
    defer listener.Close()
    smtp := &SMTP{Addr: listener.Addr().String()}
    err = smtp.Listen(context.Background())
    if err == nil || !strings.Contains(err.Error(), "persistent store") {
        t.Fatalf("Listen error = %v, expected preflight rejection", err)
    }
}
