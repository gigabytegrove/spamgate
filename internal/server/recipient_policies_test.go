package server

import (
	"bytes"
	"encoding/json"
	"github.com/gigabytegrove/spamgate/internal/core"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRecipientPolicyAdminUpdateAndRedaction(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}, {Name: "alice", Email: "alice@example.org", Role: "mailbox"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	s.sessions["admin-token"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "admin-csrf"}, Expires: time.Now().Add(time.Hour)}
	s.sessions["mailbox-token"] = session{Identity: Identity{Name: "alice", Email: "alice@example.org", Role: "mailbox", Session: true, CSRF: "mailbox-csrf"}, Expires: time.Now().Add(time.Hour)}
	call := func(method, path, cookie, csrf string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		req.Header.Set("X-CSRF-Token", csrf)
		resp := httptest.NewRecorder()
		s.Router().ServeHTTP(resp, req)
		return resp
	}
	valid := map[string]any{"policies": []map[string]any{{"mailbox": "alice@example.org", "tag_threshold": 2, "quarantine_threshold": 5, "reject_threshold": 10}}}
	if r := call("PUT", "/api/v1/recipient-policies", "admin-token", "", valid); r.Code != 403 {
		t.Fatalf("CSRF bypass: %d", r.Code)
	}
	if r := call("PUT", "/api/v1/recipient-policies", "mailbox-token", "mailbox-csrf", valid); r.Code != 403 {
		t.Fatalf("RBAC bypass: %d", r.Code)
	}
	if r := call("PUT", "/api/v1/recipient-policies", "admin-token", "admin-csrf", valid); r.Code != 200 {
		t.Fatalf("policy not accepted: %d %s", r.Code, r.Body)
	}
	bad := map[string]any{"policies": []map[string]any{{"mailbox": "alice@example.org", "tag_threshold": 10, "quarantine_threshold": 5, "reject_threshold": 20}}}
	if r := call("PUT", "/api/v1/recipient-policies", "admin-token", "admin-csrf", bad); r.Code != 400 {
		t.Fatalf("bad thresholds accepted: %d", r.Code)
	}
	if r := call("GET", "/api/v1/config", "mailbox-token", "", nil); r.Code != 200 || bytes.Contains(r.Body.Bytes(), []byte("recipient_policies")) {
		t.Fatalf("mailbox policy inventory leaked: %d %s", r.Code, r.Body)
	}
}
