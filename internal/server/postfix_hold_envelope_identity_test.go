package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestPostfixHoldEnvelopeIdentityFailsClosed(t *testing.T) {
	timestamp := time.Now().UTC()
	scan := core.Message{
		ID: core.ID(), Timestamp: timestamp, Connector: "milter",
		MTAQueueID: "AABB1234", MTAAction: "postfix_hold_requested",
		Sender:     "Sender@Example.org",
		Recipients: []string{"User@Example.org", "user@example.org"},
	}
	base := PostfixHeld{
		QueueID: scan.MTAQueueID, Sender: "Sender@EXAMPLE.ORG",
		ArrivalTime: timestamp.Unix(), RecipientCount: 2,
		Recipients: []string{"user@EXAMPLE.ORG", "User@example.org"},
	}
	if !correlatesPostfixHold(scan, base) {
		t.Fatal("complete exact local parts with folded domains did not correlate")
	}
	cases := []struct {
		name   string
		mutate func(*PostfixHeld)
	}{
		{"sender local-part case", func(h *PostfixHeld) { h.Sender = "sender@example.org" }},
		{"recipient local-part case", func(h *PostfixHeld) { h.Recipients = []string{"user@example.org", "user@example.org"} }},
		{"malformed nested sender", func(h *PostfixHeld) { h.Sender = "<<Sender@Example.org>>" }},
		{"malformed recipient", func(h *PostfixHeld) { h.Recipients[0] = "user@example.org\nBcc:evil" }},
		{"Unicode domain mismatch", func(h *PostfixHeld) { h.Recipients[0] = "user@exämple.org" }},
		{"partial recipient", func(h *PostfixHeld) { h.Recipients = h.Recipients[:1]; h.RecipientCount = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			held := base
			held.Recipients = append([]string(nil), base.Recipients...)
			tc.mutate(&held)
			if correlatesPostfixHold(scan, held) {
				t.Fatalf("unsafe held envelope correlated: %+v", held)
			}
		})
	}
}

func TestPostfixHoldHTTPRefusesLocalPartAliasBeforeAudit(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	scan := core.Message{
		ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter",
		MTAQueueID: "C0FFEE12", MTAAction: "postfix_hold_requested",
		Sender: "Sender@Example.org", Recipients: []string{"User@Example.org", "user@example.org"},
	}
	if err := store.Save(scan); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS", "true")
	t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
	srv := New(store, nil)
	srv.sessions["identity-admin"] = session{
		Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "csrf"},
		Expires:  time.Now().Add(time.Hour),
	}
	held := PostfixHeld{
		QueueID: scan.MTAQueueID, Sender: "sender@example.org",
		ArrivalTime: scan.Timestamp.Unix(), RecipientCount: 2,
		Recipients: []string{"User@example.org", "user@example.org"},
	}
	srv.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) { return []PostfixHeld{held}, nil }
	calls := 0
	srv.PostfixReleaseHeld = func(context.Context, string) (string, error) { calls++; return "submitted", nil }
	release := func() int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/"+scan.ID+"/postfix-release",
			strings.NewReader(`{"queue_id":"C0FFEE12","confirm":"release Postfix hold C0FFEE12","reason":"Administrator verified legitimate mail"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", "csrf")
		req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "identity-admin"})
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		return w.Code
	}
	if code := release(); code != http.StatusConflict {
		t.Fatalf("sender local-case alias permitted: %d", code)
	}
	held.Sender = scan.Sender
	held.Recipients = []string{"user@example.org", "user@example.org"}
	if code := release(); code != http.StatusConflict {
		t.Fatalf("recipient local-case alias permitted: %d", code)
	}
	if calls != 0 {
		t.Fatal("privileged release executed for ambiguous mailbox")
	}
	saved, ok := store.Get(scan.ID)
	if !ok || saved.MTAActionState != "" {
		t.Fatalf("refused release mutated durable audit: %+v", saved)
	}
	held.Sender = "Sender@EXAMPLE.ORG"
	held.Recipients = []string{"user@EXAMPLE.ORG", "User@example.org"}
	if code := release(); code != http.StatusAccepted {
		t.Fatalf("exact identity with domain casefold refused: %d", code)
	}
	if calls != 1 {
		t.Fatalf("expected one authorized privileged invocation, got %d", calls)
	}
}

func TestPostfixHoldInventoryRequiresExplicitEnvelopeFields(t *testing.T) {
	valid := `{"queue_name":"hold","queue_id":"ABC123","sender":"","arrival_time":1793100000,"message_size":0,"recipients":[{"address":"recipient@example.org"}]}`
	if got, err := parsePostfixHold([]byte(valid + "\n")); err != nil || len(got) != 1 {
		t.Fatalf("valid null-sender Postfix record rejected: %v, %+v", err, got)
	}
	for _, tc := range []struct{ name, raw string }{
		{"missing sender", strings.Replace(valid, `"sender":"",`, "", 1)},
		{"null sender", strings.Replace(valid, `"sender":""`, `"sender":null`, 1)},
		{"missing size", strings.Replace(valid, `"message_size":0,`, "", 1)},
		{"null size", strings.Replace(valid, `"message_size":0`, `"message_size":null`, 1)},
		{"missing recipients", strings.Replace(valid, `,"recipients":[{"address":"recipient@example.org"}]`, "", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parsePostfixHold([]byte(tc.raw + "\n")); err == nil {
				t.Fatalf("incomplete Postfix authorization evidence accepted: %+v", got)
			}
		})
	}
}
