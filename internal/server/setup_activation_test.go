package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Exercise the real authenticated API, including CSRF, persistent config and
// the source/subject/time gates. A listener alone must never activate the MTA.
func TestVerifiedActivationRequiresFreshMailFlow(t *testing.T) {
	dir := t.TempDir()
	st, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil)
	srv.Runtime.Services = map[string]RuntimeService{"milter": {Enabled: true, Address: "127.0.0.1:38472"}, "rspamd_http": {Enabled: true}}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	var cookie *http.Cookie
	var csrf string
	request := func(method, path string, obj any) (int, map[string]any) {
		t.Helper()
		var body []byte
		if obj != nil {
			body, _ = json.Marshal(obj)
		}
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		if obj != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if path == "/api/v1/setup" && res.StatusCode == 201 {
			for _, c := range res.Cookies() {
				if c.Name == "spamgate_session" {
					cookie = c
				}
			}
		}
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	setupKey := srv.setupToken
	if code, _ := request("POST", "/api/v1/setup", map[string]any{"username": "operator", "password": "correct horse battery staple", "site_name": "SpammerZZ", "setup_key": setupKey}); code != 400 {
		t.Fatalf("rename accepted during setup: %d", code)
	}
	if code, _ := request("POST", "/api/v1/setup", map[string]any{"username": "operator", "password": "correct horse battery staple", "setup_key": setupKey}); code != 201 {
		t.Fatalf("admin setup: %d", code)
	}
	_, me := request("GET", "/api/v1/me", nil)
	csrf = me["csrf"].(string)
	if code, _ := request("POST", "/api/v1/setup/monitor", map[string]any{}); code != 409 {
		t.Fatalf("monitor without plan: %d", code)
	}
	if code, _ := request("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "postfix", "mode": "local", "policy": "balanced", "activated": true, "verified_id": "fake", "probe": "SG-forged"}); code != 200 {
		t.Fatalf("save choices: %d", code)
	}
	if st.Config().Onboarding.Activated || st.Config().Onboarding.Probe != "" {
		t.Fatal("client forged activated onboarding state")
	}
	if code, _ := request("POST", "/api/v1/setup/activate", map[string]any{"delivery_confirmed": true}); code != 409 {
		t.Fatalf("activation without test: %d", code)
	}
	if code, _ := request("POST", "/api/v1/setup/monitor", map[string]any{}); code != 200 {
		t.Fatalf("arm monitoring: %d", code)
	}
	_, readiness := request("GET", "/api/v1/setup/readiness", nil)
	if readiness["state"] != "watching" || readiness["instance_running"] != false {
		t.Fatalf("incorrect initial state: %+v", readiness)
	}
	probe := readiness["probe_subject"].(string)
	if !strings.HasPrefix(probe, "SG-") {
		t.Fatalf("bad marker %q", probe)
	}
	// Previous history, wrong connector, wrong marker and rejected mail do not count.
	tests := []core.Message{
		{ID: core.ID(), Timestamp: time.Now().Add(-time.Hour), Connector: "milter", Subject: "Hello " + probe, Action: "accept"},
		{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "http", Subject: "Hello " + probe, Action: "accept"},
		{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "rspamd-http", Subject: "Hello " + probe, Action: "accept"},
		{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter", Subject: "unrelated", Action: "accept"},
		{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter", Subject: "Hello " + probe, Action: "reject"},
	}
	for _, msg := range tests {
		if err := st.Save(msg); err != nil {
			t.Fatal(err)
		}
	}
	_, readiness = request("GET", "/api/v1/setup/readiness", nil)
	if readiness["connection_verified"] != false {
		t.Fatalf("unrelated mail counted: %+v", readiness)
	}
	if code, _ := request("POST", "/api/v1/setup/activate", map[string]any{"delivery_confirmed": true}); code != 409 {
		t.Fatalf("accepted unrelated mail: %d", code)
	}
	good := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter", Subject: "Verification " + probe, Action: "tag", Score: 5}
	if err := st.Save(good); err != nil {
		t.Fatal(err)
	}
	_, readiness = request("GET", "/api/v1/setup/readiness", nil)
	if readiness["state"] != "test_detected" || readiness["instance_running"] != false {
		t.Fatalf("valid test not detected: %+v", readiness)
	}
	if code, _ := request("POST", "/api/v1/setup/activate", map[string]any{"delivery_confirmed": false}); code != 400 {
		t.Fatalf("delivery confirmation not enforced: %d", code)
	}
	if code, _ := request("POST", "/api/v1/setup/activate", map[string]any{"delivery_confirmed": true}); code != 200 {
		t.Fatalf("valid activation denied: %d", code)
	}
	_, readiness = request("GET", "/api/v1/setup/readiness", nil)
	if readiness["state"] != "running" || readiness["instance_running"] != true {
		t.Fatalf("activation not reflected: %+v", readiness)
	}
	restarted, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv2 := New(restarted, nil)
	srv2.Runtime.Services = map[string]RuntimeService{"milter": {Enabled: true}}
	if srv2.Store.Config().Onboarding.VerifiedID != good.ID {
		t.Fatal("activation not persistent")
	}
	srv2.Runtime.Services = map[string]RuntimeService{}
	if srv2.connectorEnabled("milter") {
		t.Fatal("stale listener accepted")
	}
	// Reconfigure the mail server: prior test proof must be invalidated.
	if code, _ := request("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "custom", "mode": "remote", "policy": "balanced"}); code != 200 {
		t.Fatalf("reconfigure failed: %d", code)
	}
	if st.Config().Onboarding.Activated || st.Config().Onboarding.Probe != "" {
		t.Fatal("old proof survived reconfiguration")
	}
	// Unsupported Exim/cPanel cannot activate by faking a listener.
	if code, _ := request("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "cpanel", "mode": "local", "policy": "balanced"}); code != 200 {
		t.Fatalf("cpanel plan rejected: %d", code)
	}
	if code, _ := request("POST", "/api/v1/setup/monitor", map[string]any{}); code != 409 {
		t.Fatalf("unsupported connector monitoring enabled: %d", code)
	}
}

func TestProductNameCannotBeModified(t *testing.T) {
	dir := t.TempDir()
	st, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateConfig(func(c *core.Config) error { c.Settings.SiteName = "Not SpamGate"; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := st.Config().Settings.SiteName; got != "SpamGate" {
		t.Fatalf("site name changed: %q", got)
	}
	// An older config that changed the product name is migrated on next load.
	raw, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Config().Settings.SiteName != "SpamGate" {
		t.Fatal("name migration failed")
	}
}
