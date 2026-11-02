package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestPostfixReleaseRequestRejectsAmbiguousOrHostileJSON(t *testing.T) {
	valid := "{\"queue_id\":\"ABCD1234\",\"confirm\":\"release Postfix hold ABCD1234\",\"reason\":\"Verified legitimate message by administrator\"}"
	cases := []struct {
		name string
		body string
	}{
		{"duplicate queue", strings.Replace(valid, "\"queue_id\":", "\"queue_id\":\"OTHER1234\",\"queue_id\":", 1)},
		{"case-folded alias", strings.Replace(valid, "\"queue_id\":", "\"QUEUE_ID\":\"OTHER1234\",\"queue_id\":", 1)},
		{"escaped alias", strings.Replace(valid, "\"queue_id\":", "\"queue_\\u0069d\":\"OTHER1234\",\"queue_id\":", 1)},
		{"duplicate confirmation", strings.Replace(valid, "\"confirm\":", "\"confirm\":\"fake\",\"confirm\":", 1)},
		{"duplicate reason", strings.Replace(valid, "\"reason\":", "\"reason\":\"fake\",\"reason\":", 1)},
		{"unknown field", strings.Replace(valid, "\"reason\":", "\"extra\":1,\"reason\":", 1)},
		{"trailing JSON", valid + "{}"},
		{"array root", "[" + valid + "]"},
		{"null root", "null"},
		{"invalid UTF8", valid + string([]byte{0xff})},
		{"oversized", valid + strings.Repeat(" ", postfixReleaseRequestLimit)},
		{"wrong field type", strings.Replace(valid, "\"queue_id\":\"ABCD1234\"", "\"queue_id\":123", 1)},
		{"truncated", valid[:len(valid)-1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			if decoded, err := decodePostfixReleaseRequest(req); err == nil {
				t.Fatalf("accepted unsafe release request: %+v", decoded)
			}
		})
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(valid))
	decoded, err := decodePostfixReleaseRequest(req)
	if err != nil || decoded.QueueID != "ABCD1234" || decoded.Reason == "" {
		t.Fatalf("valid request rejected: %+v %v", decoded, err)
	}
}

func TestPostfixReleaseReasonRejectsLogAndAuditInjection(t *testing.T) {
	for _, value := range []string{
		"too short", "Verified sender\nInjected: success",
		"Verified sender\rInjected: success",
		"Verified sender\tInjected: success",
		"Verified sender\u2028Injected: success",
		"Verified sender\u2029Injected: success",
		strings.Repeat("A", 513),
	} {
		if validPostfixReleaseReason(value) {
			t.Fatalf("accepted unsafe audit reason %q", value)
		}
	}
	if !validPostfixReleaseReason("Verified legitimate message by administrator") {
		t.Fatal("rejected ordinary administrator reason")
	}
}

func TestPostfixReleaseHTTPAuthorizationAuditAndErrorPrivacy(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{
			{Name: "admin", Role: "admin"},
			{Name: "mailbox", Role: "mailbox", Email: "alice@example.org"},
		}
		return nil
	}); err != nil { t.Fatal(err) }
	scan := core.Message{
		ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter",
		MTAQueueID: "ABCD1234", MTAAction: "postfix_hold_requested",
		Sender: "sender@example.net", Recipients: []string{"alice@example.org", "bob@example.org"},
		Action: "quarantine",
	}
	if err := store.Save(scan); err != nil { t.Fatal(err) }
	t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
	t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS", "true")
	srv := New(store, nil)
	srv.sessions["admin-session"] = session{
		Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "csrf"},
		Expires: time.Now().Add(time.Hour),
	}
	srv.sessions["mailbox-session"] = session{
		Identity: Identity{Name: "mailbox", Role: "mailbox", Email: "alice@example.org", Session: true, CSRF: "csrf"},
		Expires: time.Now().Add(time.Hour),
	}
	held := PostfixHeld{
		QueueID: scan.MTAQueueID, Sender: scan.Sender, ArrivalTime: scan.Timestamp.Unix(),
		Recipients: []string{"bob@example.org", "alice@example.org"}, RecipientCount: 2,
	}
	inventoryCalls, commandCalls := 0, 0
	srv.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) {
		inventoryCalls++
		return []PostfixHeld{held}, nil
	}
	srv.PostfixReleaseHeld = func(context.Context, string) (string, error) {
		commandCalls++
		return "postsuper accepted", nil
	}
	body := fmt.Sprintf("{\"queue_id\":%q,\"confirm\":%q,\"reason\":%q}",
		scan.MTAQueueID, "release Postfix hold "+scan.MTAQueueID,
		"Verified legitimate message by administrator")
	call := func(id, cookie, csrf, origin, payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/"+id+"/postfix-release", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" { req.Header.Set("X-CSRF-Token", csrf) }
		if origin != "" { req.Header.Set("Origin", origin) }
		if cookie != "" { req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: cookie}) }
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		return w
	}
	for _, tc := range []struct {
		name, id, cookie, csrf, origin, payload string
		status int
	}{
		{"unauthenticated", scan.ID, "", "", "", body, 401},
		{"mailbox", scan.ID, "mailbox-session", "csrf", "", body, 403},
		{"missing CSRF", scan.ID, "admin-session", "", "", body, 403},
		{"foreign origin", scan.ID, "admin-session", "csrf", "https://attacker.example", body, 403},
		{"unknown scan", "unknown", "admin-session", "csrf", "", body, 404},
		{"duplicate key", scan.ID, "admin-session", "csrf", "", strings.Replace(body, "\"queue_id\":", "\"queue_id\":\"OTHER1234\",\"queue_id\":", 1), 400},
		{"unknown field", scan.ID, "admin-session", "csrf", "", strings.Replace(body, "\"reason\":", "\"other\":\"value\",\"reason\":", 1), 400},
		{"control in reason", scan.ID, "admin-session", "csrf", "", strings.Replace(body, "Verified legitimate message by administrator", "Verified\\nInjected by attacker", 1), 400},
		{"wrong confirmation", scan.ID, "admin-session", "csrf", "", strings.Replace(body, "release Postfix hold ABCD1234", "release all mail", 1), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := call(tc.id, tc.cookie, tc.csrf, tc.origin, tc.payload)
			if w.Code != tc.status { t.Fatalf("HTTP %d, expected %d: %s", w.Code, tc.status, w.Body.String()) }
		})
	}
	if inventoryCalls != 0 || commandCalls != 0 {
		t.Fatalf("invalid HTTP requests touched Postfix: inventory=%d command=%d", inventoryCalls, commandCalls)
	}
	if saved, ok := store.Get(scan.ID); !ok || saved.MTAActionState != "" {
		t.Fatalf("invalid HTTP requests changed durable audit: %+v", saved)
	}
	w := call(scan.ID, "admin-session", "csrf", "", body)
	if w.Code != http.StatusAccepted || commandCalls != 1 || inventoryCalls != 1 {
		t.Fatalf("valid HTTP release failed: %d %s inventory=%d command=%d", w.Code, w.Body.String(), inventoryCalls, commandCalls)
	}
	saved, ok := store.Get(scan.ID)
	if !ok || saved.MTAActionState != "release_submitted" || saved.OverrideBy != "admin" ||
		saved.Delivery != "postfix_release_submitted" || len(saved.Findings) < 2 {
		t.Fatalf("missing durable release evidence: %+v", saved)
	}
	if w := call(scan.ID, "admin-session", "csrf", "", body); w.Code != 409 || commandCalls != 1 {
		t.Fatalf("duplicate release permitted: %d %s", w.Code, w.Body.String())
	}
	// A failed privileged command must not echo host details to the browser,
	// and the durable attempted state must prevent blind retries.
	failed := scan
	failed.ID = core.ID()
	failed.MTAQueueID = "ABCD5678"
	if err := store.Save(failed); err != nil { t.Fatal(err) }
	held.QueueID = failed.MTAQueueID
	srv.PostfixReleaseHeld = func(context.Context, string) (string, error) {
		commandCalls++
		return "", errors.New("private host path /etc/postfix/private.conf")
	}
	failedBody := strings.ReplaceAll(body, "ABCD1234", "ABCD5678")
	w = call(failed.ID, "admin-session", "csrf", "", failedBody)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "/etc/postfix") {
		t.Fatalf("privileged error leaked to browser: %d %s", w.Code, w.Body.String())
	}
	saved, ok = store.Get(failed.ID)
	if !ok || saved.MTAActionState != "release_attempted" {
		t.Fatalf("failed command did not retain durable attempted state: %+v", saved)
	}
	if w := call(failed.ID, "admin-session", "csrf", "", failedBody); w.Code != 409 || commandCalls != 2 {
		t.Fatalf("blind retry permitted: %d %s", w.Code, w.Body.String())
	}
}
