package server

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPostfixHoldCorrelationRequiresCompleteEnvelope(t *testing.T) {
    timestamp := time.Unix(1793400000, 0).UTC()
    scan := core.Message{
        ID: core.ID(), Timestamp: timestamp, Connector: "milter",
        MTAQueueID: "ABC123", MTAAction: "postfix_hold_requested",
        Sender: "Sender@example.org",
        Recipients: []string{"alice@example.org", "bob@example.org"},
    }
    held := PostfixHeld{
        QueueID: "ABC123", Sender: "sender@example.org",
        ArrivalTime: timestamp.Unix(), RecipientCount: 2,
        Recipients: []string{"BOB@example.org", "alice@example.org"},
    }
    if !correlatesPostfixHold(scan, held) {
        t.Fatal("reordered, case-insensitive complete envelope did not correlate")
    }
    cases := []struct {
        name string
        change func(*core.Message, *PostfixHeld)
    }{
        {"different sender", func(_ *core.Message, h *PostfixHeld) { h.Sender = "other@example.org" }},
        {"partial recipients", func(_ *core.Message, h *PostfixHeld) { h.Recipients = h.Recipients[:1]; h.RecipientCount = 1 }},
        {"unrelated recipient", func(_ *core.Message, h *PostfixHeld) { h.Recipients[1] = "mallory@example.org" }},
        {"duplicate recipient", func(_ *core.Message, h *PostfixHeld) { h.Recipients[1] = h.Recipients[0] }},
        {"truncated inventory", func(_ *core.Message, h *PostfixHeld) { h.RecipientsTruncated = true }},
        {"inconsistent count", func(_ *core.Message, h *PostfixHeld) { h.RecipientCount = 3 }},
        {"missing count", func(_ *core.Message, h *PostfixHeld) { h.RecipientCount = 0 }},
        {"missing arrival", func(_ *core.Message, h *PostfixHeld) { h.ArrivalTime = 0 }},
        {"reused queue ID", func(_ *core.Message, h *PostfixHeld) { h.ArrivalTime += 3600 }},
        {"wrong queue ID", func(_ *core.Message, h *PostfixHeld) { h.QueueID = "DEF123" }},
        {"wrong connector", func(m *core.Message, _ *PostfixHeld) { m.Connector = "smtp" }},
        {"no hold action", func(m *core.Message, _ *PostfixHeld) { m.MTAAction = "accept" }},
        {"empty recipient", func(_ *core.Message, h *PostfixHeld) { h.Recipients[0] = "" }},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            m := scan
            m.Recipients = append([]string(nil), scan.Recipients...)
            h := held
            h.Recipients = append([]string(nil), held.Recipients...)
            tc.change(&m, &h)
            if correlatesPostfixHold(m, h) {
                t.Fatalf("unsafe correlation for %s", tc.name)
            }
        })
    }
    scan.Sender = ""
    held.Sender = ""
    if !correlatesPostfixHold(scan, held) {
        t.Fatal("matching null reverse path must remain supported")
    }
}

func TestPostfixHoldInventoryNeverLabelsUnrelatedQueueAsSpamGateScan(t *testing.T) {
    store, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    if err := store.UpdateConfig(func(c *core.Config) error {
        c.SetupComplete = true
        c.Users = []core.User{{Name: "admin", Role: "admin"}}
        return nil
    }); err != nil { t.Fatal(err) }
    scan := core.Message{
        ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter",
        MTAQueueID: "ACED1234", MTAAction: "postfix_hold_requested",
        Sender: "sender@example.org", Recipients: []string{"alice@example.org", "bob@example.org"},
    }
    if err := store.Save(scan); err != nil { t.Fatal(err) }
    t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
    srv := New(store, nil)
    srv.sessions["hold-admin"] = session{
        Identity: Identity{Name: "admin", Role: "admin", Session: true},
        Expires: time.Now().Add(time.Hour),
    }
    held := []PostfixHeld{{
        QueueID: scan.MTAQueueID, Sender: scan.Sender, ArrivalTime: scan.Timestamp.Unix(),
        Recipients: []string{"alice@example.org", "bob@example.org"}, RecipientCount: 2,
    }}
    srv.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) { return held, nil }
    inspect := func() string {
        t.Helper()
        req := httptest.NewRequest(http.MethodGet, "/api/v1/postfix/hold-queue", nil)
        req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "hold-admin"})
        response := httptest.NewRecorder()
        srv.Router().ServeHTTP(response, req)
        if response.Code != http.StatusOK { t.Fatalf("inventory HTTP %d: %s", response.Code, response.Body.String()) }
        var payload struct { Messages []PostfixHeld `json:"messages"` }
        if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil { t.Fatal(err) }
        if len(payload.Messages) != len(held) { t.Fatalf("unexpected inventory: %+v", payload.Messages) }
        return payload.Messages[0].SpamGateScanID
    }
    if got := inspect(); got != scan.ID { t.Fatalf("matching inventory lost scan correlation: %q", got) }
    held[0].Recipients = []string{"alice@example.org"}
    held[0].RecipientCount = 1
    if got := inspect(); got != "" { t.Fatalf("partial recipient set labelled as scan: %q", got) }
    held[0].Recipients = []string{"alice@example.org", "bob@example.org"}
    held[0].RecipientCount = 2
    held[0].ArrivalTime += 3600
    if got := inspect(); got != "" { t.Fatalf("reused queue ID labelled as scan: %q", got) }
    held[0].ArrivalTime = scan.Timestamp.Unix()
    held = append(held, held[0])
    if got := inspect(); got != "" { t.Fatalf("ambiguous duplicate queue ID labelled as scan: %q", got) }
}

func TestPostfixHoldReleaseRefusesPartialRecipientOwnership(t *testing.T) {
    store, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    if err := store.UpdateConfig(func(c *core.Config) error {
        c.SetupComplete = true
        c.Users = []core.User{{Name: "admin", Role: "admin"}}
        return nil
    }); err != nil { t.Fatal(err) }
    scan := core.Message{
        ID: core.ID(), Timestamp: time.Now().UTC(), Connector: "milter",
        MTAQueueID: "ABCD1234", MTAAction: "postfix_hold_requested",
        Sender: "sender@example.org", Recipients: []string{"alice@example.org", "bob@example.org"},
    }
    if err := store.Save(scan); err != nil { t.Fatal(err) }
    t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS", "true")
    t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
    srv := New(store, nil)
    srv.sessions["release-admin"] = session{
        Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "csrf"},
        Expires: time.Now().Add(time.Hour),
    }
    held := []PostfixHeld{{
        QueueID: scan.MTAQueueID, Sender: scan.Sender, ArrivalTime: scan.Timestamp.Unix(),
        Recipients: []string{"alice@example.org"}, RecipientCount: 1,
    }}
    srv.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) { return held, nil }
    calls := 0
    srv.PostfixReleaseHeld = func(context.Context, string) (string, error) {
        calls++
        return "submitted", nil
    }
    release := func() int {
        t.Helper()
        req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/"+scan.ID+"/postfix-release",
            strings.NewReader(`{"queue_id":"ABCD1234","confirm":"release Postfix hold ABCD1234","reason":"Verified legitimate message by administrator"}`))
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-CSRF-Token", "csrf")
        req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "release-admin"})
        response := httptest.NewRecorder()
        srv.Router().ServeHTTP(response, req)
        return response.Code
    }
    if code := release(); code != http.StatusConflict { t.Fatalf("partial recipient hold released: HTTP %d", code) }
    held[0].Recipients = []string{"alice@example.org", "mallory@example.org"}
    held[0].RecipientCount = 2
    if code := release(); code != http.StatusConflict { t.Fatalf("unrelated recipient hold released: HTTP %d", code) }
    if calls != 0 { t.Fatal("unsafe Postfix release command was executed") }
    held[0].Recipients = []string{"bob@example.org", "alice@example.org"}
    if code := release(); code != http.StatusAccepted { t.Fatalf("complete envelope release rejected: HTTP %d", code) }
    if calls != 1 { t.Fatalf("expected one Postfix invocation, got %d", calls) }
}
