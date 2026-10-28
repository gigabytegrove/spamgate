package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestHeadersEndpointRBACPrivacyAndLegacy(t *testing.T) {
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
	headers := []byte("From: sender@example.com\r\nTo: alice@example.org\r\nReceived: from secret.internal\r\nSubject: Test")
	m := core.Message{ID: core.ID(), Timestamp: time.Now(), Recipients: []string{"alice@example.org", "bob@example.org"}, Action: "accept", HeaderSnapshot: headers}
	if err = st.Save(m); err != nil {
		t.Fatal(err)
	}
	old := core.Message{ID: core.ID(), Timestamp: time.Now(), Action: "accept"}
	if err = st.Save(old); err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil)
	srv.sessions["admin-cookie"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true}, Expires: time.Now().Add(time.Hour)}
	srv.sessions["user-cookie"] = session{Identity: Identity{Name: "alice", Email: "alice@example.org", Role: "mailbox", Session: true}, Expires: time.Now().Add(time.Hour)}
	request := func(path, cookie string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		}
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		return w
	}
	url := "/api/v1/messages/" + m.ID + "/headers"
	if w := request(url, ""); w.Code != 401 {
		t.Fatalf("anonymous headers got %d", w.Code)
	}
	if w := request(url, "user-cookie"); w.Code != 403 || strings.Contains(w.Body.String(), "secret.internal") {
		t.Fatalf("mailbox raw headers leaked: %d %s", w.Code, w.Body.String())
	}
	if w := request(url, "admin-cookie"); w.Code != 200 || !strings.Contains(w.Body.String(), "secret.internal") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admin headers failed: %d %s", w.Code, w.Body.String())
	}
	if w := request("/api/v1/messages", "admin-cookie"); strings.Contains(w.Body.String(), "secret.internal") {
		t.Fatal("raw headers leaked in normal message listing")
	}
	if w := request("/api/v1/messages/"+old.ID+"/headers", "admin-cookie"); w.Code != 404 || !strings.Contains(w.Body.String(), "not retained") {
		t.Fatalf("missing headers invented: %d %s", w.Code, w.Body.String())
	}
}
