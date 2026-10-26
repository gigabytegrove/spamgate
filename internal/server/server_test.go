package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestHTTPSetupScanAndRBAC(t *testing.T) {
	st, e := core.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s := New(st, nil)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	admin := &http.Client{}
	var cookie *http.Cookie
	var csrf string
	call := func(client *http.Client, method, path string, v any, token string) (int, map[string]any) {
		t.Helper()
		var body []byte
		if v != nil {
			body, _ = json.Marshal(v)
		}
		r, e := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if v != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != nil && token == "" {
			r.AddCookie(cookie)
			if csrf != "" {
				r.Header.Set("X-CSRF-Token", csrf)
			}
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if cookie == nil && resp.StatusCode == 201 && path == "/api/v1/setup" {
			for _, c := range resp.Cookies() {
				if c.Name == "spamgate_session" {
					cookie = c
				}
			}
		}
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return resp.StatusCode, result
	}
	if code, _ := call(admin, "POST", "/api/v1/setup", map[string]string{"username": "admin", "password": "long secure password", "site_name": "SpamGate", "setup_key": "wrong"}, ""); code != 403 {
		t.Fatal("setup should require claim key", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/setup", map[string]string{"username": "admin", "password": "long secure password", "site_name": "SpamGate", "setup_key": s.setupToken}, ""); code != 201 {
		t.Fatal("setup failed", code)
	}
	if cookie == nil {
		t.Fatal("session cookie missing")
	}
	code, me := call(admin, "GET", "/api/v1/me", nil, "")
	if code != 200 {
		t.Fatalf("/me %v", code)
	}
	csrf, _ = me["csrf"].(string)
	if csrf == "" {
		t.Fatal("CSRF missing")
	}
	if code, _ := call(admin, "POST", "/api/v1/setup", map[string]string{"username": "other", "password": "long secure password", "site_name": "Other", "setup_key": s.setupToken}, ""); code != 403 {
		t.Fatal("setup replay not rejected")
	}
	if code, _ := call(admin, "POST", "/api/v1/rules", map[string]any{"name": "Blocked", "kind": "sender_domain", "value": "blocked.example", "score": 21, "enabled": true}, ""); code != 201 {
		t.Fatal("rule creation failed", code)
	}
	payload := []byte("From: abuse@blocked.example\r\nTo: user@example.com\r\nSubject: hi\r\n\r\nbody")
	r, e := http.NewRequest("POST", ts.URL+"/api/v1/scan", bytes.NewReader(payload))
	if e != nil {
		t.Fatal(e)
	}
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("X-SpamGate-Sender", "abuse@blocked.example")
	r.Header.Set("X-SpamGate-Recipients", "user@example.com")
	resp, e := admin.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	var msg core.Message
	_ = json.NewDecoder(resp.Body).Decode(&msg)
	resp.Body.Close()
	if resp.StatusCode != 200 || msg.Action != "reject" {
		t.Fatalf("scan failed %d %+v", resp.StatusCode, msg)
	}
	if code, v := call(admin, "GET", "/api/v1/messages/"+msg.ID, nil, ""); code != 200 || v["action"] != "reject" {
		t.Fatal("message missing", code, v)
	}
	if code, _ := call(admin, "POST", "/api/v1/messages/"+msg.ID+"/override", map[string]string{"action": "accept", "reason": "Operator verified sender"}, ""); code != 200 {
		t.Fatal("override failed", code)
	}
	if code, v := call(admin, "POST", "/api/v1/tokens", map[string]string{"name": "smtp-adapter", "scope": "scan"}, ""); code != 201 || !strings.HasPrefix(v["token"].(string), "sg_") {
		t.Fatal("key issue failed", code, v)
	} else {
		key := v["token"].(string)
		if code, _ := call(admin, "GET", "/api/v1/messages", nil, key); code != 403 {
			t.Fatal("scan token accessed history", code)
		}
	}
	if code, _ := call(admin, "POST", "/api/v1/users", map[string]string{"name": "alice", "email": "user@example.com", "password": "a unique password for Alice"}, ""); code != 201 {
		t.Fatal("mailbox user creation failed", code)
	}
	if code, v := call(admin, "GET", "/api/v1/config", nil, ""); code != 200 {
		t.Fatal(code)
	} else {
		us := v["users"].([]any)
		for _, x := range us {
			if x.(map[string]any)["password_hash"] != "" {
				t.Fatal("hash disclosed")
			}
		}
	}
}
func TestSecurityHeadersAndMethods(t *testing.T) {
	st, _ := core.Open(t.TempDir())
	s := New(st, nil)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SpamGate") {
		t.Fatal("UI not served")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("CSP missing")
	}
}

func TestMailboxPrivacyAndQuarantineDiscard(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = append(c.Users,
			core.User{Name: "admin", Role: "admin"},
			core.User{Name: "alice", Email: "alice@example.org", Role: "mailbox"},
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Sender: "sender@example.net", Recipients: []string{"alice@example.org", "bob@example.org"}, Action: "quarantine", Delivery: "quarantined", Connector: "smtp"}
	if err := st.Quarantine(m.ID, []byte("Subject: held\r\n\r\nPrivate")); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(m); err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	s.sessions["alice-cookie"] = session{Identity: Identity{Name: "alice", Email: "alice@example.org", Role: "mailbox", Session: true, CSRF: "a"}, Expires: time.Now().Add(time.Hour)}
	s.sessions["admin-cookie"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "b"}, Expires: time.Now().Add(time.Hour)}
	router := s.Router()
	call := func(method, path, cookie, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/v1/messages", "/api/v1/messages/" + m.ID} {
		w := call("GET", path, "alice-cookie", "")
		if w.Code != 200 {
			t.Fatalf("mailbox history %s: %d", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "bob@example.org") {
			t.Fatalf("co-recipient leaked at %s", path)
		}
	}
	if w := call("GET", "/api/v1/statistics", "unknown", ""); w.Code != 401 {
		t.Fatalf("missing identity saw stats: %d", w.Code)
	}
	if w := call("DELETE", "/api/v1/messages/"+m.ID+"/quarantine", "alice-cookie", "a"); w.Code != 403 {
		t.Fatalf("mailbox deleted hold: %d", w.Code)
	}
	if w := call("DELETE", "/api/v1/messages/"+m.ID+"/quarantine", "admin-cookie", "b"); w.Code != 200 {
		t.Fatalf("admin discard: %d %s", w.Code, w.Body.String())
	}
	if _, err := st.Quarantined(m.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original not deleted: %v", err)
	}
	stored, _ := st.Get(m.ID)
	if stored.Delivery != "discarded" || stored.OverrideBy != "admin" {
		t.Fatalf("discard not audited: %+v", stored)
	}
	if w := call("DELETE", "/api/v1/messages/"+m.ID+"/quarantine", "admin-cookie", "b"); w.Code != 409 {
		t.Fatalf("repeat discard should conflict: %d", w.Code)
	}
}

func TestSignalPoliciesRBACAndPersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = append(c.Users, core.User{Name: "admin", Role: "admin"}, core.User{Name: "alice", Email: "alice@example.org", Role: "mailbox"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	s.sessions["admin-test"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "adm"}, Expires: time.Now().Add(time.Hour)}
	s.sessions["alice-test"] = session{Identity: Identity{Name: "alice", Email: "alice@example.org", Role: "mailbox", Session: true, CSRF: "usr"}, Expires: time.Now().Add(time.Hour)}
	invoke := func(cookie, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		req.Header.Set("X-CSRF-Token", map[string]string{"admin-test": "adm", "alice-test": "usr"}[cookie])
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		return w
	}
	if w := invoke("alice-test", "PUT", "/api/v1/signals/MISSING_FROM", `{"score":4,"enabled":false}`); w.Code != 403 {
		t.Fatalf("mailbox edited signals: %d", w.Code)
	}
	if w := invoke("admin-test", "PUT", "/api/v1/signals/NONEXISTENT", `{"score":4,"enabled":false}`); w.Code != 404 {
		t.Fatalf("unknown signal accepted: %d", w.Code)
	}
	if w := invoke("admin-test", "PUT", "/api/v1/signals/MISSING_FROM", `{"score":101,"enabled":false}`); w.Code != 400 {
		t.Fatalf("invalid weight accepted: %d", w.Code)
	}
	if w := invoke("admin-test", "PUT", "/api/v1/signals/MISSING_FROM", `{"score":9,"enabled":false}`); w.Code != 200 {
		t.Fatalf("signal update: %d %s", w.Code, w.Body.String())
	}
	if w := invoke("alice-test", "GET", "/api/v1/signals", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"score":9`) {
		t.Fatalf("mailbox signals view: %d %s", w.Code, w.Body.String())
	}
	reopened, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := reopened.Config().SignalPolicies["MISSING_FROM"]
	if p.Enabled || p.Score != 9 {
		t.Fatalf("persisted signal changed: %+v", p)
	}
}

func TestBayesTrainingAPIAccessControl(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}, {Name: "mailbox", Role: "mailbox", Email: "user@example.org"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	s.sessions["admin"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "correct"}, Expires: time.Now().Add(time.Hour)}
	s.sessions["mailbox"] = session{Identity: Identity{Name: "mailbox", Role: "mailbox", Email: "user@example.org", Session: true, CSRF: "correct"}, Expires: time.Now().Add(time.Hour)}
	sample := []byte("From: sender@example.org\r\nSubject: Verify your account now\r\n\r\nConfirm password security account identity immediately today")
	call := func(user, csrf string) int {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/v1/bayes/train?label=spam", bytes.NewReader(sample))
		req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: user})
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res := httptest.NewRecorder()
		s.Router().ServeHTTP(res, req)
		return res.Code
	}
	if code := call("mailbox", "correct"); code != 403 {
		t.Fatal("mailbox trained global classifier", code)
	}
	if code := call("admin", ""); code != 403 {
		t.Fatal("missing CSRF allowed", code)
	}
	if code := call("admin", "correct"); code != 200 {
		t.Fatal("admin train failed", code)
	}
	if st.BayesStats().Spam != 1 {
		t.Fatal("admin training not persisted")
	}
	req := httptest.NewRequest("GET", "/api/v1/bayes/stats", nil)
	req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "mailbox"})
	out := httptest.NewRecorder()
	s.Router().ServeHTTP(out, req)
	if out.Code != 403 {
		t.Fatal("mailbox read global model statistics", out.Code)
	}
}
