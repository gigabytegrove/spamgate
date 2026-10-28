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
	pages := []string{"/", "/overview", "/messages", "/rules", "/signals", "/learning", "/blocklists", "/mailboxes", "/api-keys", "/policy", "/settings", "/settings/updates", "/connections", "/help", "/diagnostics", "/quarantine", "/investigations", "/threat-intelligence", "/scan-workbench", "/welcome"}
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
	for _, path := range []string{"/assets/app.css", "/assets/redesign.css", "/assets/app.js"} {
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

// The listener inventory must never be disclosed to unauthenticated clients.
func TestRuntimeRequiresAdmin(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(store, nil)
	srv.Runtime = RuntimeStatus{Services: map[string]RuntimeService{
		"milter": {Enabled: true, Address: "127.0.0.1:38472", Detail: "configured"},
	}}
	resp := httptest.NewRecorder()
	srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/v1/runtime", nil))
	if resp.Code != http.StatusServiceUnavailable || strings.Contains(resp.Body.String(), "38472") {
		t.Fatalf("unauthenticated runtime inventory leaked: %d %s", resp.Code, resp.Body.String())
	}
}

// Mail host inventory exposes MTA metadata only to authenticated administrators.
func TestHostInventoryRequiresAdmin(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(store, nil)
	resp := httptest.NewRecorder()
	srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/v1/host", nil))
	if resp.Code != http.StatusServiceUnavailable || strings.Contains(resp.Body.String(), "mail_server") {
		t.Fatalf("host inventory leaked: HTTP %d %s", resp.Code, resp.Body.String())
	}
}

func TestBrandAssetsAreTransparentAndEmbedded(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(store, nil)
	for _, path := range []string{"/assets/spamgate-logo.png", "/assets/spamgate-icon.png", "/assets/favicon.png"} {
		resp := httptest.NewRecorder()
		srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
		if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "image/png" || resp.Body.Len() < 1000 {
			t.Fatalf("brand image %s HTTP %d, bytes %d", path, resp.Code, resp.Body.Len())
		}
		if resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("brand image %s caching unexpected", path)
		}
	}
	resp := httptest.NewRecorder()
	srv.Router().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/assets/not-a-logo.png", nil))
	if resp.Code != http.StatusNotFound {
		t.Fatalf("unexpected brand image returned HTTP %d", resp.Code)
	}
}
