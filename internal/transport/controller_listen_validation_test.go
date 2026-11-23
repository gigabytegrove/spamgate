package transport

import (
    "context"
    "errors"
    "strings"
    "testing"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestControllerListenAddressValidation(t *testing.T) {
    for _, tc := range []struct {
        name, addr string
        valid bool
    }{
        {"ipv4", "127.0.0.1:38474", true},
        {"ipv6", "[::1]:38474", true},
        {"hostname", "localhost:38474", true},
        {"wildcard", ":38474", true},
        {"min-port", "127.0.0.1:1", true},
        {"max-port", "127.0.0.1:65535", true},
        {"missing-port", "127.0.0.1:", false},
        {"zero-port", "127.0.0.1:0", false},
        {"negative-port", "127.0.0.1:-1", false},
        {"overflow-port", "127.0.0.1:65536", false},
        {"service-name", "127.0.0.1:smtp", false},
        {"space-port", "127.0.0.1: 80", false},
        {"suffix-port", "127.0.0.1:80x", false},
        {"unbracketed-ipv6", "::1:38474", false},
        {"host-newline", "bad\nhost:38474", false},
    } {
        t.Run(tc.name, func(t *testing.T) {
            err := validateControllerListenAddress(tc.addr)
            if (err == nil) != tc.valid {
                t.Fatalf("address %q valid=%t, error=%v", tc.addr, tc.valid, err)
            }
        })
    }
}

func TestControllerEnvRejectsInvalidPortBeforeServiceStart(t *testing.T) {
    store, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    t.Setenv("SPAMGATE_CONTROLLER_TOKEN", strings.Repeat("z", 32))
    t.Setenv("SPAMGATE_CONTROLLER_TRUSTED_CIDRS", "127.0.0.1/32")
    for _, addr := range []string{"127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:smtp"} {
        t.Run(addr, func(t *testing.T) {
            t.Setenv("SPAMGATE_CONTROLLER_LISTEN", addr)
            if _, err := ControllerFromEnv(store); err == nil {
                t.Fatalf("invalid listen address %q accepted", addr)
            }
        })
    }
}

func TestControllerListenDoesNotBindWhenCancelled(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    controller := &RspamdController{ListenAddress: "127.0.0.1:38474"}
    if err := controller.Listen(ctx); !errors.Is(err, context.Canceled) {
        t.Fatalf("cancelled listener returned %v, want context.Canceled", err)
    }
    if err := controller.Listen(nil); err == nil {
        t.Fatal("nil context accepted")
    }
    var nilController *RspamdController
    if err := nilController.Listen(context.Background()); err == nil {
        t.Fatal("nil controller accepted")
    }
}
