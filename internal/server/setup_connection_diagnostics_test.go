package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/hostinspect"
)

func TestSetupShowsDisconnectedPostfixAndRefusesActivation(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil)
	srv.Runtime.Services = map[string]RuntimeService{"milter": {Enabled: true, Address: "127.0.0.1:38472"}}
	linked := false
	srv.InspectHost = func(context.Context) hostinspect.Report {
		return hostinspect.Report{MailServer: "postfix", MilterReady: true, PostfixConfigured: linked}
	}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	var cookie *http.Cookie
	csrf := ""
	request := func(method, path string, obj any) (int, map[string]any) {
		t.Helper()
		data, _ := json.Marshal(obj)
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(data))
		if obj != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if path == "/api/v1/setup" && resp.StatusCode == 201 {
			for _, c := range resp.Cookies() {
				if c.Name == "spamgate_session" {
					cookie = c
				}
			}
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, res := request("POST", "/api/v1/setup", map[string]any{"username": "operator", "password": "safe test password for setup", "setup_key": srv.setupToken}); code != 201 {
		t.Fatalf("setup failed %d %v", code, res)
	}
	_, me := request("GET", "/api/v1/me", nil)
	csrf = me["csrf"].(string)
	if code, _ := request("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "postfix", "mode": "local", "policy": "balanced"}); code != 200 {
		t.Fatalf("onboarding: %d", code)
	}
	_, readiness := request("GET", "/api/v1/setup/readiness", nil)
	if readiness["state"] != "postfix_not_connected" || readiness["postfix_connection"] != "disconnected" || readiness["instance_running"] != false {
		t.Fatalf("claimed protection with detached Postfix: %v", readiness)
	}
	// Even an otherwise-valid proof cannot activate a detached Postfix instance.
	if code, _ := request("POST", "/api/v1/setup/monitor", map[string]any{}); code != 200 {
		t.Fatalf("monitor: %d", code)
	}
	probe := st.Config().Onboarding.Probe
	other := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter", Subject: "ordinary legitimate mail", Action: "accept"}
	good := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter", Subject: probe, Action: "accept"}
	for _, m := range []core.Message{other, good} {
		if err := st.Save(m); err != nil {
			t.Fatal(err)
		}
	}
	_, readiness = request("GET", "/api/v1/setup/readiness", nil)
	if readiness["connector_messages_since_test"].(float64) != 2 || readiness["connection_verified"] != false || readiness["instance_running"] != false {
		t.Fatalf("missing evidence breakdown: %v", readiness)
	}
	if code, _ := request("POST", "/api/v1/setup/activate", map[string]any{"delivery_confirmed": true}); code != 409 {
		t.Fatalf("detached Postfix allowed activation: %d", code)
	}
	// Simulate user reattaching Postfix. Invalidate short cache for test.
	linked = true
	srv.hostMu.Lock()
	srv.hostChecked = time.Time{}
	srv.hostMu.Unlock()
	_, readiness = request("GET", "/api/v1/setup/readiness", nil)
	if readiness["state"] != "test_detected" || readiness["postfix_connection"] != "connected" {
		t.Fatalf("reattached Postfix not recognized: %v", readiness)
	}
	if code, _ := request("POST", "/api/v1/setup/activate", map[string]any{"delivery_confirmed": true}); code != 200 {
		t.Fatalf("activation failed: %d", code)
	}
	linked = false
	srv.hostMu.Lock()
	srv.hostChecked = time.Time{}
	srv.hostMu.Unlock()
	_, readiness = request("GET", "/api/v1/setup/readiness", nil)
	if readiness["instance_running"] != false || readiness["state"] != "postfix_not_connected" {
		t.Fatalf("lost Milter attachment still shown running: %v", readiness)
	}
}
