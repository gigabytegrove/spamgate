package server

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// Sensitive queue metadata and irreversible-action responses must not be
// retained by shared proxies or browser caches, including authorization errors.
func TestMailQueueEndpointsAlwaysDisableCaching(t *testing.T) {
    store, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    s := New(store, nil)
    cases := []struct{
        name string
        method string
        path string
        handler func(http.ResponseWriter, *http.Request)
    }{
        {"postfix inventory", "GET", "/api/v1/postfix/holds", s.postfixHoldQueue},
        {"postfix release", "POST", "/api/v1/messages/example/postfix-release", s.postfixReleaseMessage},
        {"delivery inventory", "GET", "/api/v1/delivery/queue", s.deliveryQueue},
        {"delivery retry", "POST", "/api/v1/delivery/queue/example/retry", s.retryDelivery},
        {"delivery discard", "POST", "/api/v1/delivery/queue/example/discard", s.discardDelivery},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            req := httptest.NewRequest(tc.method, tc.path, nil)
            w := httptest.NewRecorder()
            tc.handler(w, req)
            if got := w.Header().Get("Cache-Control"); got != "no-store" {
                t.Fatalf("sensitive endpoint cache policy = %q; want no-store", got)
            }
        })
    }
}
