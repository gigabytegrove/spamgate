package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestUIRoutesServeEmbeddedInterface(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(store, nil)
	pages := []string{"/", "/overview", "/messages", "/rules", "/signals", "/learning", "/blocklists", "/mailboxes", "/api-keys", "/policy", "/connections", "/help"}
	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			resp := httptest.NewRecorder()
			srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
			if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "<title>SpamGate") {
				t.Fatalf("route %s: HTTP %d", path, resp.Code)
			}
		})
	}
	for _, path := range []string{"/unexpected", "/admin", "/this/does/not/exist"} {
		resp := httptest.NewRecorder()
		srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
		if resp.Code != http.StatusNotFound {
			t.Fatalf("unknown path %s got %d", path, resp.Code)
		}
	}
	for _, path := range []string{"/assets/app.css", "/assets/app.js"} {
		resp := httptest.NewRecorder()
		srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
		if got := resp.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("asset %s has stale-cache policy %q", path, got)
		}
		if resp.Code != http.StatusOK || resp.Body.Len() < 1000 {
			t.Fatalf("asset %s got %d bytes HTTP %d", path, resp.Body.Len(), resp.Code)
		}
	}
}
