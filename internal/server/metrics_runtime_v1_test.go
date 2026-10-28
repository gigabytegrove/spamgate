package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestMetricsRequireAdminAndExposeMeasuredLatency(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}, {Name: "alice", Role: "mailbox", Email: "alice@example.org"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	s.sessions["admin"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true}, Expires: time.Now().Add(time.Hour)}
	s.sessions["alice"] = session{Identity: Identity{Name: "alice", Role: "mailbox", Session: true, Email: "alice@example.org"}, Expires: time.Now().Add(time.Hour)}
	router := s.Router()
	request := func(cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if status := request("").Code; status != 401 {
		t.Fatalf("public access: %d", status)
	}
	if status := request("alice").Code; status != 403 {
		t.Fatalf("mailbox access: %d", status)
	}
	w := request("admin")
	if w.Code != 200 {
		t.Fatalf("admin access: %d", w.Code)
	}
	output, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"spamgate_runtime_scans_total", "spamgate_runtime_scan_errors_total", "spamgate_runtime_scan_duration_seconds_bucket", "spamgate_runtime_scan_actions_total"} {
		if !strings.Contains(string(output), line) {
			t.Fatalf("metric %s absent", line)
		}
	}
	if strings.Contains(string(output), "alice@example.org") {
		t.Fatal("leaked mailbox label")
	}
}
