//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/transport"
)

// Isolated DNS ensures the forced local HOLD rule, not external DNS
// availability, determines the disposable integration case.
type postfixHTTPStubDNS struct{}

func (postfixHTTPStubDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if strings.HasPrefix(name, "_dmarc.") {
		return []string{"v=DMARC1; p=none"}, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}
func (postfixHTTPStubDNS) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}
func (postfixHTTPStubDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}

// Run only on a disposable CI Linux VM, with the real narrow root-owned
// helper installed and this test binary executed as the spamgate account.
// No production host, mail queue or configuration may be touched.
func TestRealPostfixHoldReleaseThroughAdminHTTP(t *testing.T) {
	if os.Getenv("SPAMGATE_DISPOSABLE_POSTFIX_HTTP_LAB") != "1" {
		t.Skip("requires explicitly authorized disposable Postfix HTTP lab")
	}
	if os.Getenv("CI") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("refusing live Postfix HTTP test outside disposable CI")
	}
	current, err := user.Current()
	if err != nil || current.Username != "spamgate" || os.Geteuid() == 0 {
		t.Fatalf("live HTTP helper test must run unprivileged as spamgate: %v", err)
	}
	const recipient = "spamgatebeta@localhost"
	const sender = "hold-http-lab@example.org"
	const messageID = "spamgate-http-hold@example.org"
	t.Setenv("SPAMGATE_TEST_RECIPIENTS", recipient)
	t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "true")
	t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS", "true")
	store, err := core.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}}
		c.Rules = append(c.Rules, core.Rule{
			ID: "disposable-http-hold", Name: "Disposable HTTP hold release",
			Kind: "sender_email", Value: sender, Action: "quarantine", Enabled: true,
		})
		return nil
	}); err != nil { t.Fatal(err) }

	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	milter := &transport.Milter{
		Addr: "127.0.0.1:38472", Trusted: []*net.IPNet{trusted},
		Store: store, Scanner: &core.Scanner{Store: store, Resolver: postfixHTTPStubDNS{}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- milter.Listen(ctx) }()
	ready := false
	for i := 0; i < 80; i++ {
		conn, dialErr := net.DialTimeout("tcp", milter.Addr, 200*time.Millisecond)
		if dialErr == nil { _ = conn.Close(); ready = true; break }
		time.Sleep(50 * time.Millisecond)
	}
	if !ready { t.Fatal("Milter listener not ready") }

	payload := []byte(fmt.Sprintf(
		"From: <%s>\r\nTo: <%s>\r\nMessage-ID: <%s>\r\nSubject: disposable HTTP Postfix hold\r\n\r\nHarmless administrative release fixture.\r\n",
		sender, recipient, messageID))
	if err := smtp.SendMail("127.0.0.1:25", nil, sender, []string{recipient}, payload); err != nil {
		t.Fatalf("real Postfix refused held SMTP fixture: %v", err)
	}

	var scan core.Message
	var held PostfixHeld
	found := false
	for i := 0; i < 100; i++ {
		scans := store.List(10, "")
		inventory, invErr := readPostfixHold(context.Background())
		if invErr != nil { t.Fatalf("real unprivileged postqueue inventory failed: %v", invErr) }
		if len(scans) > 0 {
			for _, item := range inventory {
				if item.Sender == sender && item.QueueID == scans[0].MTAQueueID &&
					correlatesPostfixHold(scans[0], item) {
					scan, held, found = scans[0], item, true
					break
				}
			}
		}
		if found { break }
		time.Sleep(100 * time.Millisecond)
	}
	if !found { t.Fatal("real SMTP/Milter HOLD never correlated to unprivileged Postfix inventory") }
	if scan.MTAAction != "postfix_hold_requested" || scan.Action != "quarantine" {
		t.Fatalf("unexpected real Milter disposition: %s / %s", scan.MTAAction, scan.Action)
	}
	t.Logf("Real SMTP HOLD correlated with scan=%s queue=%s", scan.ID, held.QueueID)

	srv := New(store, nil)
	srv.sessions["disposable-admin"] = session{
		Identity: Identity{Name: "admin", Role: "admin", Session: true, CSRF: "disposable-csrf"},
		Expires: time.Now().Add(time.Hour),
	}
	httpServer := httptest.NewServer(srv.Router())
	defer httpServer.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	get := func() *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/postfix/hold-queue", nil)
		if err != nil { t.Fatal(err) }
		req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "disposable-admin"})
		resp, err := client.Do(req)
		if err != nil { t.Fatal(err) }
		return resp
	}
	resp := get()
	var inventoryResponse struct {
		Enabled bool `json:"enabled"`
		Messages []PostfixHeld `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inventoryResponse); err != nil { t.Fatal(err) }
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !inventoryResponse.Enabled {
		t.Fatalf("real HTTP hold inventory unavailable: %d", resp.StatusCode)
	}
	correlated := false
	for _, item := range inventoryResponse.Messages {
		if item.QueueID == held.QueueID && item.SpamGateScanID == scan.ID {
			correlated = true
		}
	}
	if !correlated { t.Fatal("HTTP inventory did not identify exact real held scan") }

	requestBody := fmt.Sprintf("{\"queue_id\":%q,\"confirm\":%q,\"reason\":%q}",
		held.QueueID, "release Postfix hold "+held.QueueID,
		"Verified legitimate disposable SMTP hold by administrator")
	release := func(csrf string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost,
			httpServer.URL+"/api/v1/messages/"+scan.ID+"/postfix-release",
			bytes.NewBufferString(requestBody))
		if err != nil { t.Fatal(err) }
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" { req.Header.Set("X-CSRF-Token", csrf) }
		req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: "disposable-admin"})
		resp, err := client.Do(req)
		if err != nil { t.Fatal(err) }
		defer resp.Body.Close()
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		return resp.StatusCode, body.String()
	}
	if code, body := release(""); code != http.StatusForbidden {
		t.Fatalf("CSRF bypass on live hold: %d %s", code, body)
	}
	if code, body := release("disposable-csrf"); code != http.StatusAccepted {
		t.Fatalf("real unprivileged HTTP-to-helper release failed: %d %s", code, body)
	}
	saved, ok := store.Get(scan.ID)
	if !ok || saved.MTAActionState != "release_submitted" ||
		saved.Delivery != "postfix_release_submitted" || saved.OverrideBy != "admin" {
		t.Fatalf("real helper success did not persist audit: %+v", saved)
	}
	if code, body := release("disposable-csrf"); code != http.StatusConflict {
		t.Fatalf("real duplicate privileged release permitted: %d %s", code, body)
	}
	// Postfix may transition to active/deferred before Dovecot delivery.
	// The workflow independently checks the exact mailbox receipt.
	for i := 0; i < 100; i++ {
		items, err := readPostfixHold(context.Background())
		if err != nil { t.Fatal(err) }
		stillHeld := false
		for _, item := range items {
			if item.QueueID == held.QueueID { stillHeld = true }
		}
		if !stillHeld { break }
		if i == 99 { t.Fatal("Postfix queue remained on HOLD after successful helper release") }
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("HTTP administrator release submitted via unprivileged native helper: queue=%s", held.QueueID)
	cancel()
	select {
	case err := <-done:
		if err != nil { t.Fatalf("Milter shutdown: %v", err) }
	case <-time.After(3 * time.Second):
		t.Fatal("Milter listener did not stop")
	}
}
