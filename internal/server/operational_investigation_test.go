package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestInvestigationUsesEvidenceAndDoesNotClaimDelivery(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}, {Name: "mb", Role: "mailbox", Email: "user@example.org"}}
		return nil
	})
	msg := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), MessageID: "<match@example.org>", Connector: "milter", MTAQueueID: "AB123", MTAAction: "postfix_hold_requested", Sender: "sender@example.net", Recipients: []string{"user@example.org"}, Action: "quarantine"}
	if err = st.Save(msg); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "mail.log")
	if err = os.WriteFile(log, []byte("Oct 28 host postfix/smtp[44]: AB123: to=<user@example.org>, status=sent\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPAMGATE_POSTFIX_LOG_PATH", log)
	t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
	s := New(st, nil)
	s.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) {
		return []PostfixHeld{{QueueID: "AB123", Recipients: []string{"user@example.org"}}}, nil
	}
	s.sessions["administrator"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true}, Expires: time.Now().Add(time.Hour)}
	s.sessions["mailbox"] = session{Identity: Identity{Name: "mb", Role: "mailbox", Email: "user@example.org", Session: true}, Expires: time.Now().Add(time.Hour)}
	test := func(cookie string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/messages/"+msg.ID+"/investigation", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		}
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("cookie=%s got=%d %s", cookie, w.Code, w.Body.String())
		}
		return w
	}
	test("", 401)
	test("mailbox", 403)
	w := test("administrator", 200)
	var value investigationResult
	if err = json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value.PostfixHoldPresent == nil || !*value.PostfixHoldPresent || len(value.PostfixLogEvents) != 1 {
		t.Fatalf("missing correlated evidence: %+v", value)
	}
	for _, step := range value.Steps {
		if strings.Contains(strings.ToLower(step.Detail), "delivered to inbox") || strings.Contains(strings.ToLower(step.Detail), "delivery confirmed") {
			t.Fatalf("false delivery claim: %s", step.Detail)
		}
	}
}

func TestPostfixReleaseAuthorizationCorrelationAndDurableAudit(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}, {Name: "mb", Role: "mailbox", Email: "user@example.org"}}
		return nil
	})
	msg := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter", MTAQueueID: "AF123", MTAAction: "postfix_hold_requested", Sender: "sender@example.net", Recipients: []string{"user@example.org"}, Action: "quarantine"}
	if err = st.Save(msg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
	t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS", "true")
	s := New(st, nil)
	held := []PostfixHeld{{QueueID: "AF123", Sender: "sender@example.net", Recipients: []string{"user@example.org"}, RecipientCount: 1, ArrivalTime: msg.Timestamp.Unix()}}
	s.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) { return held, nil }
	calls := 0
	s.PostfixReleaseHeld = func(ctx context.Context, id string) (string, error) {
		calls++
		if id != "AF123" {
			t.Fatalf("unexpected ID %q", id)
		}
		stored, _ := st.Get(msg.ID)
		if stored.MTAActionState != "release_attempted" {
			t.Fatal("release invoked before durable audit")
		}
		return "released 1 message", nil
	}
	s.sessions["administrator"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "token"}, Expires: time.Now().Add(time.Hour)}
	s.sessions["mailbox"] = session{Identity: Identity{Name: "mb", Role: "mailbox", Email: "user@example.org", Session: true, CSRF: "token"}, Expires: time.Now().Add(time.Hour)}
	send := func(cookie, body, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/v1/messages/"+msg.ID+"/postfix-release", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie})
		}
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		return w
	}
	good := `{"queue_id":"AF123","confirm":"release Postfix hold AF123","reason":"Verified false positive by operator"}`
	if w := send("", good, "token"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := send("mailbox", good, "token"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := send("administrator", good, ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := send("administrator", `{"queue_id":"AF123","confirm":"wrong","reason":"Reason that is sufficiently long"}`, "token"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if calls != 0 {
		t.Fatal("release command ran before authorization")
	}
	held[0].Recipients = []string{"other@example.org"}
	if w := send("administrator", good, "token"); w.Code != 409 {
		t.Fatal("mismatch allowed", w.Code, w.Body.String())
	}
	held[0].Recipients = []string{"user@example.org"}
	held[0].Sender = "mismatched@example.net"
	if w := send("administrator", good, "token"); w.Code != 409 {
		t.Fatal("mismatched sender allowed", w.Code, w.Body.String())
	}
	held[0].Sender = "sender@example.net"
	held[0].ArrivalTime = time.Now().Add(-72 * time.Hour).Unix()
	if w := send("administrator", good, "token"); w.Code != 409 {
		t.Fatal("reused ID allowed", w.Code, w.Body.String())
	}
	held[0].ArrivalTime = msg.Timestamp.Unix()
	if w := send("administrator", good, "token"); w.Code != 202 {
		t.Fatalf("release failed: %d %s", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Fatal("release not submitted once", calls)
	}
	if w := send("administrator", good, "token"); w.Code != 409 {
		t.Fatalf("repeat release accepted: %d", w.Code)
	}
	stored, _ := st.Get(msg.ID)
	if stored.MTAActionState != "release_submitted" || stored.Delivery != "postfix_release_submitted" || len(stored.Findings) != 2 {
		t.Fatalf("audit missing: %+v", stored)
	}
	reopened, err := core.Open(st.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	persistent, _ := reopened.Get(msg.ID)
	if persistent.MTAActionState != "release_submitted" {
		t.Fatal("release audit not persisted")
	}
}
