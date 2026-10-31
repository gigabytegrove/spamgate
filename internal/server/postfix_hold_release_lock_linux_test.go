//go:build linux

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestPostfixReleaseLockSerializesIndependentHandles(t *testing.T) {
	dir := t.TempDir()
	first, err := acquirePostfixHoldReleaseLock(context.Background(), dir)
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if second, err := acquirePostfixHoldReleaseLock(ctx, dir); err == nil {
		second()
		first()
		t.Fatal("second independent handle acquired an already-held release lock")
	}
	first()
	// Unlock is idempotent and must not accidentally close a reused descriptor.
	first()
	next, err := acquirePostfixHoldReleaseLock(context.Background(), dir)
	if err != nil { t.Fatalf("lock remained unavailable after release: %v", err) }
	next()
}

func TestPostfixReleaseLockRejectsUnsafeFilesystem(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, nil, 0600); err != nil { t.Fatal(err) }
		if err := os.Symlink(target, filepath.Join(dir, postfixHoldReleaseLockName)); err != nil { t.Skip(err) }
		if unlock, err := acquirePostfixHoldReleaseLock(context.Background(), dir); err == nil {
			unlock()
			t.Fatal("followed a symlinked release lock")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, nil, 0600); err != nil { t.Fatal(err) }
		if err := os.Link(target, filepath.Join(dir, postfixHoldReleaseLockName)); err != nil { t.Skip(err) }
		if unlock, err := acquirePostfixHoldReleaseLock(context.Background(), dir); err == nil {
			unlock()
			t.Fatal("accepted a multiply-linked release lock")
		}
	})
	t.Run("writable-lock", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, postfixHoldReleaseLockName)
		if err := os.WriteFile(path, nil, 0666); err != nil { t.Fatal(err) }
		if err := os.Chmod(path, 0666); err != nil { t.Fatal(err) }
		if unlock, err := acquirePostfixHoldReleaseLock(context.Background(), dir); err == nil {
			unlock()
			t.Fatal("accepted a world-writable release lock")
		}
	})
	t.Run("writable-directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0777); err != nil { t.Fatal(err) }
		if unlock, err := acquirePostfixHoldReleaseLock(context.Background(), dir); err == nil {
			unlock()
			t.Fatal("accepted a world-writable data directory")
		}
	})
}

func TestPostfixReleaseHandlerRefusesContendedCrossProcessLock(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name:"admin", Role:"admin"}}
		return nil
	}); err != nil { t.Fatal(err) }
	msg := core.Message{
		ID:core.ID(), Timestamp:time.Now().UTC(), Connector:"milter",
		MTAQueueID:"ABCD1234", MTAAction:"postfix_hold_requested",
		Sender:"sender@example.org", Recipients:[]string{"alice@example.org"},
	}
	if err := store.Save(msg); err != nil { t.Fatal(err) }
	t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
	t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS", "true")
	srv := New(store, nil)
	srv.sessions["lock-admin"] = session{
		Identity:Identity{Name:"admin",Role:"admin",Session:true,CSRF:"csrf"},
		Expires:time.Now().Add(time.Hour),
	}
	inventoryCalls, releaseCalls := 0, 0
	srv.PostfixHeldInventory = func(context.Context) ([]PostfixHeld, error) {
		inventoryCalls++
		return []PostfixHeld{{
			QueueID:msg.MTAQueueID, Sender:msg.Sender, ArrivalTime:msg.Timestamp.Unix(),
			Recipients:[]string{"alice@example.org"}, RecipientCount:1,
		}}, nil
	}
	srv.PostfixReleaseHeld = func(context.Context, string) (string,error) {
		releaseCalls++
		return "release accepted", nil
	}
	request := func(ctx context.Context) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"queue_id":"ABCD1234","confirm":"release Postfix hold ABCD1234","reason":"Verified legitimate message by administrator"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/"+msg.ID+"/postfix-release", strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", "csrf")
		req.AddCookie(&http.Cookie{Name:"spamgate_session",Value:"lock-admin"})
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		return w
	}
	unlock, err := acquirePostfixHoldReleaseLock(context.Background(), dir)
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	blocked := request(ctx)
	if blocked.Code != http.StatusServiceUnavailable {
		unlock()
		t.Fatalf("contended lock response %d: %s", blocked.Code, blocked.Body.String())
	}
	if inventoryCalls != 0 || releaseCalls != 0 {
		unlock()
		t.Fatal("read inventory or executed release while another process held lock")
	}
	persisted, ok := store.Get(msg.ID)
	if !ok || persisted.MTAActionState != "" {
		unlock()
		t.Fatalf("contended lock changed durable release state: %+v", persisted)
	}
	unlock()
	success := request(context.Background())
	if success.Code != http.StatusAccepted || inventoryCalls != 1 || releaseCalls != 1 {
		t.Fatalf("release after lock freed: HTTP %d, inventory %d, command %d: %s",
			success.Code, inventoryCalls, releaseCalls, success.Body.String())
	}
}
