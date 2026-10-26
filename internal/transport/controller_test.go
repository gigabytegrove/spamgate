package transport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestControllerAuthenticationIsolationAndLearning(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil {
		t.Fatal(err)
	}
	cidrs, err := parseTrustedCIDRs("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "controller-secret-for-unit-tests-123"
	c := &RspamdController{Trusted: cidrs, Token: secret, Store: st}
	ts := httptest.NewServer(c.Handler())
	defer ts.Close()
	call := func(method, path, password string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if password != "" {
			req.Header.Set("Password", password)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	if code, _ := call("GET", "/stat", "", nil); code != 401 {
		t.Fatalf("missing token: %d", code)
	}
	if code, _ := call("GET", "/stat", "bad", nil); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	for _, path := range []string{"/actions", "/symbols", "/stat", "/ping"} {
		if code, _ := call("GET", path, secret, nil); code != 200 {
			t.Fatalf("%s status %d", path, code)
		}
	}
	if code, _ := call("GET", "/api/v1/config", secret, nil); code != 404 {
		t.Fatalf("controller exposed admin path: %d", code)
	}
	if code, _ := call("POST", "/fuzzyadd", secret, nil); code != 404 {
		t.Fatalf("unsupported fuzzyadd accepted: %d", code)
	}
	raw := []byte("From: trainer@example.org\r\nSubject: urgent account verification\r\n\r\nPlease verify your account by contacting our agent for urgent security account confirmation now.")
	code, body := call("POST", "/learnspam", secret, raw)
	if code != 200 || !bytes.Contains(body, []byte(`"success":true`)) {
		t.Fatalf("learnspam %d: %s", code, body)
	}
	if stats := st.BayesStats(); stats.Spam != 1 {
		t.Fatal(stats)
	}
	// Controller is required to reject untrusted peers even with the correct token.
	foreign, _ := parseTrustedCIDRs("192.0.2.1/32")
	c.Trusted = foreign
	if code, _ := call("GET", "/stat", secret, nil); code != 403 {
		t.Fatalf("untrusted peer %d", code)
	}
}
func TestControllerStartupRequiresSecretAndCIDR(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPAMGATE_CONTROLLER_LISTEN", "0.0.0.0:38474")
	t.Setenv("SPAMGATE_CONTROLLER_TOKEN", "short")
	if _, err := ControllerFromEnv(st); err == nil || !strings.Contains(err.Error(), "TOKEN") {
		t.Fatal("no secret allowed", err)
	}
	t.Setenv("SPAMGATE_CONTROLLER_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("SPAMGATE_CONTROLLER_TRUSTED_CIDRS", "")
	if _, err := ControllerFromEnv(st); err == nil {
		t.Fatal("missing CIDRs allowed")
	}
	t.Setenv("SPAMGATE_CONTROLLER_TRUSTED_CIDRS", "192.0.2.8/32")
	if c, err := ControllerFromEnv(st); err != nil || c.ListenAddress != "0.0.0.0:38474" {
		t.Fatal(c, err)
	}
}
