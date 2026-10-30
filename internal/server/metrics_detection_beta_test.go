package server

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestBetaDetectionMetricsAreAdminOnlyAndHaveFixedLabels(t *testing.T) {
    st, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    if err := st.UpdateConfig(func(c *core.Config) error {
        c.SetupComplete = true
        c.Users = []core.User{{Name: "admin", Role: "admin"}}
        return nil
    }); err != nil { t.Fatal(err) }
    s := New(st, nil)
    s.sessions["admin"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true}, Expires: time.Now().Add(time.Hour)}
    req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
    unauthorized := httptest.NewRecorder()
    s.Router().ServeHTTP(unauthorized, req)
    if unauthorized.Code != http.StatusUnauthorized { t.Fatalf("public metrics: %d", unauthorized.Code) }
    req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "admin"})
    authorized := httptest.NewRecorder()
    s.Router().ServeHTTP(authorized, req)
    if authorized.Code != http.StatusOK { t.Fatalf("admin metrics: %d", authorized.Code) }
    output := authorized.Body.String()
    for _, symbol := range core.RuntimeDetectionSymbols() {
        if !strings.Contains(output, "spamgate_runtime_detection_messages_total{symbol=\""+symbol+"\"}") {
            t.Fatalf("missing fixed detection metric for %s", symbol)
        }
    }
    if strings.Contains(output, "user@example.org") { t.Fatal("private mailbox leaked in metrics") }
}
