package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestSessionsSurviveRestartAndLogout(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	w := httptest.NewRecorder()
	if err := s.newSession(w, Identity{Name: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	s2 := New(store, nil)
	if len(s2.sessions) != 1 {
		t.Fatalf("session not restored: %d", len(s2.sessions))
	}
	if got := s2.sessions[cookie.Value].Identity.CSRF; got == "" {
		t.Fatal("csrf lost")
	}
	s2.mu.Lock()
	delete(s2.sessions, cookie.Value)
	err = s2.persistSessionsLocked()
	s2.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s3 := New(store, nil)
	if len(s3.sessions) != 0 {
		t.Fatal("revoked session resurrected")
	}
}
func TestExpiredSessionsNotRestored(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	s.sessions["expired"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "csrf"}, Expires: time.Now().Add(-time.Second)}
	s.mu.Lock()
	err = s.persistSessionsLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(New(store, nil).sessions) != 0 {
		t.Fatal("expired session restored")
	}
}
func TestSessionFilePrivate(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if err := s.newSession(httptest.NewRecorder(), Identity{Name: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(store.DataDir(), "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", st.Mode())
	}
}
