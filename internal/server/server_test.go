package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
