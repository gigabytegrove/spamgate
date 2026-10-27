package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestGuidedSetupAndOneClickReview(t *testing.T) {
	dir := t.TempDir()
	st, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	type reply struct {
		Status int
		Value  map[string]any
	}
	var session *http.Cookie
	csrf := ""
	call := func(method, path string, v any) reply {
		t.Helper()
		payload, _ := json.Marshal(v)
		req, e := http.NewRequest(method, ts.URL+path, bytes.NewReader(payload))
		if e != nil {
			t.Fatal(e)
		}
		if v != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if session != nil {
			req.AddCookie(session)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		if path == "/api/v1/setup" && res.StatusCode == 201 {
			for _, c := range res.Cookies() {
				if c.Name == "spamgate_session" {
					session = c
				}
			}
		}
		var result map[string]any
		_ = json.NewDecoder(res.Body).Decode(&result)
		return reply{res.StatusCode, result}
	}
	if r := call("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "testing", "mode": "test", "policy": "balanced"}); r.Status != 503 {
		t.Fatalf("unauthenticated wizard access: %d", r.Status)
	}
	if r := call("POST", "/api/v1/setup", map[string]string{"username": "operator", "password": "long safe password 234!", "site_name": "SpamGate", "setup_key": srv.setupToken}); r.Status != 201 {
		t.Fatalf("setup: %+v", r)
	}
	if r := call("GET", "/api/v1/me", nil); r.Status != 200 {
		t.Fatalf("me %d", r.Status)
	} else {
		csrf = r.Value["csrf"].(string)
	}
	if st.Config().Onboarding.Completed {
		t.Fatal("account creation must not silently finish mail setup")
	}
	if r := call("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "cpanel", "mode": "local", "policy": "unknown"}); r.Status != 400 {
		t.Fatalf("bad protection preset accepted: %d", r.Status)
	}
	if r := call("PUT", "/api/v1/onboarding", map[string]any{"completed": true, "server": "testing", "mode": "test", "policy": "careful"}); r.Status != 200 {
		t.Fatalf("wizard save %d %+v", r.Status, r.Value)
	}
	c := st.Config()
	if !c.Onboarding.Completed || c.Onboarding.Server != "testing" || c.Settings.TagThreshold != 7 {
		t.Fatalf("wizard choices did not persist: %+v", c)
	}
	msg := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Sender: "trusted@example.net", Recipients: []string{"alice@example.org"}, Subject: "Invoice", Action: "quarantine", Delivery: "quarantined", Score: 12, Findings: []core.Finding{{Symbol: "RISKY_ATTACHMENT", Score: 5, Detail: "invoice.docm"}}}
	if err := st.Save(msg); err != nil {
		t.Fatal(err)
	}
	if r := call("POST", "/api/v1/messages/"+msg.ID+"/review", map[string]any{"decision": "not_spam", "trust_sender": true}); r.Status != 200 {
		t.Fatalf("review failed %d %+v", r.Status, r.Value)
	}
	revised, exists := st.Get(msg.ID)
	if !exists || revised.ReviewStatus != "not_spam" || revised.Action != "accept" || revised.OriginalAction != "quarantine" || revised.Delivery != "quarantined" {
		t.Fatalf("review rewrote delivery or lost audit: %+v", revised)
	}
	c = st.Config()
	if len(c.Rules) != 1 || c.Rules[0].Kind != "sender_email" || c.Rules[0].Value != "trusted@example.net" || c.Rules[0].Action != "accept" {
		t.Fatalf("exact sender exception missing: %+v", c.Rules)
	}
	if r := call("POST", "/api/v1/messages/"+msg.ID+"/review", map[string]any{"decision": "wrong", "trust_sender": false}); r.Status != 400 {
		t.Fatalf("invalid review accepted: %d", r.Status)
	}
	opened, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Config().Onboarding.Completed {
		t.Fatal("onboarding lost across restart")
	}
	if stored, ok := opened.Get(msg.ID); !ok || stored.ReviewedBy != "operator" {
		t.Fatalf("review lost across restart %+v", stored)
	}
}
