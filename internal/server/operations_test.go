package server

import (
	"bytes"
	"encoding/json"
	"github.com/gigabytegrove/spamgate/internal/core"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOperationsSearchRuleEditAndDryRun(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	token, hash, err := core.MakeToken()
	if err != nil {
		t.Fatal(err)
	}
	err = store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Tokens = []core.Token{{Name: "test-admin", Hash: hash, Scope: "admin", Created: time.Now()}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := New(store, nil).Router()
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, req)
		return rr
	}
	raw := []byte("From: hello@localhost\r\nTo: person@localhost\r\nDate: Tue, 01 Jan 2030 00:00:00 +0000\r\nMessage-ID: <test@localhost>\r\nSubject: sample\r\n\r\nHello there\r\n")
	sim := request("POST", "/api/v1/scan/simulate", raw)
	if sim.Code != 200 {
		t.Fatalf("simulation HTTP %d: %s", sim.Code, sim.Body.String())
	}
	if store.Stats("")["total"] != 0 {
		t.Fatal("simulation wrote history")
	}
	create := request("POST", "/api/v1/rules", []byte(`{"name":"Block bad domain","kind":"sender_domain","value":"bad.invalid","score":5,"action":"reject","enabled":true,"priority":200}`))
	if create.Code != 201 {
		t.Fatalf("create rule HTTP %d: %s", create.Code, create.Body.String())
	}
	var rule core.Rule
	if err := json.Unmarshal(create.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	update := request("PUT", "/api/v1/rules/"+rule.ID, []byte(`{"name":"Block bad domain","kind":"sender_domain","value":"bad.invalid","score":8,"action":"reject","enabled":false,"priority":300}`))
	if update.Code != 200 {
		t.Fatalf("update HTTP %d: %s", update.Code, update.Body.String())
	}
	cfg := store.Config()
	if len(cfg.Rules) != 1 || cfg.Rules[0].Enabled || cfg.Rules[0].Priority != 300 {
		t.Fatalf("rule edit was not saved: %+v", cfg.Rules)
	}
	search := request("GET", "/api/v1/history/search?limit=10&q=none", nil)
	if search.Code != 200 {
		t.Fatalf("search HTTP %d: %s", search.Code, search.Body.String())
	}
	metrics := request("GET", "/api/v1/metrics", nil)
	if metrics.Code != 200 || !bytes.Contains(metrics.Body.Bytes(), []byte("spamgate_history_messages")) {
		t.Fatalf("metrics HTTP %d: %s", metrics.Code, metrics.Body.String())
	}
	unauthorized := httptest.NewRecorder()
	server.ServeHTTP(unauthorized, httptest.NewRequest("GET", "/api/v1/metrics", nil))
	if unauthorized.Code != 401 {
		t.Fatal("metrics publicly accessible")
	}
}
