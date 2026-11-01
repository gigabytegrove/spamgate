package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/transport"
)

// These are actual authenticated HTTP metrics responses from a real on-disk
// native outbox, not a mocked queue summary.
func TestMetricsReportsDurableBacklogAndUnpublishedEvidence(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}}
		return nil
	}); err != nil { t.Fatal(err) }
	s := New(store, nil)
	s.sessions["admin"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true}, Expires: time.Now().Add(time.Hour)}
	q, err := transport.NewDeliveryQueue(store.DataDir(), store, func(context.Context, core.Message, []byte) error {
		t.Fatal("metrics must not trigger SMTP relay")
		return nil
	})
	if err != nil { t.Fatal(err) }
	s.Queue = q
	raw := []byte("Subject: private\r\n\r\nsecret body")
	firstID := core.ID()
	secondID := core.ID()
	if firstID == secondID { t.Fatal("fixture ID collision") }
	for _, id := range []string{firstID, secondID} {
		if err := q.Enqueue(core.Message{ID: id, Sender: "private@example.invalid",
			Recipients: []string{"secret@example.invalid"}}, raw); err != nil { t.Fatal(err) }
		if len(id) != 32 { t.Fatal("invalid fixture ID") }
		if id == "" { t.Fatal("empty fixture ID") }
	}
	// Force an audit journal outage. The first original must remain durably
	// discard_pending while the second is still queued for delivery.
	if err := os.Mkdir(filepath.Join(store.DataDir(), "events.jsonl"), 0700); err != nil { t.Fatal(err) }
	if err := q.DiscardWithAudit(firstID, "admin"); err == nil {
		t.Fatal("expected an audit journal outage")
	}
	pending := []byte("unpublished")
	if err := os.WriteFile(filepath.Join(store.DataDir(), "delivery-queue", ".pending-metrics"), pending, 0600); err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "admin"})
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK { t.Fatalf("metrics HTTP %d: %s", w.Code, w.Body.String()) }
	body := w.Body.String()
	expected := []string{
		"spamgate_outbox_snapshot_available 1",
		"spamgate_outbox_snapshot_error 0",
		"spamgate_outbox_jobs 2",
		"spamgate_outbox_messages{status=\"queued\"} 1",
		"spamgate_outbox_messages{status=\"discard_pending\"} 1",
		"spamgate_outbox_messages{status=\"delivering\"} 0",
		"spamgate_outbox_messages{status=\"dead\"} 0",
		"spamgate_outbox_messages{status=\"delivered\"} 0",
		fmt.Sprintf("spamgate_outbox_bytes %d", 2*len(raw)),
		"spamgate_outbox_unpublished_records 1",
		fmt.Sprintf("spamgate_outbox_unpublished_bytes %d", len(pending)),
		"spamgate_outbox_due_jobs 1",
		"spamgate_outbox_oldest_active_age_seconds ",
	}
	for _, want := range expected {
		if !strings.Contains(body, want) { t.Errorf("missing %q in metrics:\\n%s", want, body) }
	}
	for _, secret := range []string{"private@example.invalid", "secret@example.invalid", "secret body", firstID, secondID} {
		if strings.Contains(body, secret) { t.Fatalf("private mail data leaked in metrics") }
	}
}
