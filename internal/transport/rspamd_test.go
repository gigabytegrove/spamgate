package transport

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestRspamdHTTPWireAndIsolation(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, cidr, err := net.ParseCIDR("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	worker := &RspamdWorker{Trusted: []*net.IPNet{cidr}, Token: "mta-secret", Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	srv := httptest.NewServer(worker.Handler())
	defer srv.Close()
	client := srv.Client()
	makeRequest := func(path, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader([]byte("From: sender@example.org\r\nTo: target@example.org\r\nDate: Mon, 26 Oct 2026 14:00:00 +0000\r\nMessage-ID: <abc@example.org>\r\nSubject: verify your account\r\n\r\nconfirm your password")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", token)
		req.Header.Set("Rcpt", "target@example.org")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	response := makeRequest("/checkv2", "Bearer wrong")
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}
	response = makeRequest("/checkv2", "Bearer mta-secret")
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatalf("expected setup required, got %d", response.StatusCode)
	}
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil {
		t.Fatal(err)
	}
	response = makeRequest("/checkv2", "Bearer mta-secret")
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	var out struct {
		Score   float64        `json:"score"`
		Action  string         `json:"action"`
		Symbols map[string]any `json:"symbols"`
		ScanID  string         `json:"scan_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ScanID == "" || len(out.Symbols) == 0 || out.Score < 5 {
		t.Fatalf("unexpected wire reply %+v", out)
	}
	request, err := http.NewRequest(http.MethodGet, srv.URL+"/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer mta-secret")
	status, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	status.Body.Close()
	if status.StatusCode != 200 {
		t.Fatal(status.StatusCode)
	}
	// Never expose management API via worker listener.
	response = makeRequest("/api/v1/config", "Bearer mta-secret")
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatalf("admin endpoint reached worker: %d", response.StatusCode)
	}
}
