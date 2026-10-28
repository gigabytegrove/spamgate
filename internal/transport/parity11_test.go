package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func startPolicyMilter(t *testing.T, mode string, rewrite bool, extra func(*core.Config), capabilities uint32) (*core.Store, net.Conn, chan error) {
	t.Helper()
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Settings.QuarantineMode = mode
		c.Settings.SubjectRewrite = rewrite
		c.Rules = []core.Rule{{ID: "force_this", Name: "Force for test", Kind: "subject_contains", Value: "sample", Action: "quarantine", Enabled: true}}
		if extra != nil {
			extra(c)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	m := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	done := make(chan error, 1)
	go func() { done <- m.handle(context.Background(), server) }()
	opts := make([]byte, 12)
	binary.BigEndian.PutUint32(opts[:4], 6)
	binary.BigEndian.PutUint32(opts[4:8], capabilities)
	milterSend(t, client, 'O', 'O', opts)
	return store, client, done
}
func policyMessage(t *testing.T, c net.Conn, subject string, forged bool) {
	t.Helper()
	milterSend(t, c, 'M', 'c', []byte("<mailer@example.org>\x00"))
	milterSend(t, c, 'R', 'c', []byte("<user@example.net>\x00"))
	for _, field := range []string{"From\x00mailer@example.org\x00", "Subject\x00" + subject + "\x00", "Date\x00Tue, 27 Oct 2026 12:00:00 +0000\x00"} {
		milterSend(t, c, 'L', 'c', []byte(field))
	}
	if forged {
		milterSend(t, c, 'L', 'c', []byte("X-SpamGate-Action\x00quarantine\x00"))
		milterSend(t, c, 'L', 'c', []byte("X-Spam\x00Yes\x00"))
		milterSend(t, c, 'L', 'c', []byte("X-Spam-Status\x00Yes, score=999\x00"))
	}
	milterSend(t, c, 'N', 'c', nil)
	milterSend(t, c, 'B', 'c', []byte("Normal delivery\r\n"))
}
func closePolicyMilter(t *testing.T, c net.Conn, done chan error) {
	t.Helper()
	milterSend(t, c, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("milter did not exit")
	}
}
func TestQuarantineToJunkAddsHeadersRatherThanHolding(t *testing.T) {
	store, c, done := startPolicyMilter(t, "junk", false, nil, milterAddHeader|milterQuarantine|milterChangeHeader)
	policyMessage(t, c, "sample quarantine", false)
	milterSend(t, c, 'E', 'h', nil)
	for _, name := range []string{"X-Spam-Status", "X-SpamGate-Score", "X-SpamGate-Action", "X-SpamGate-ID"} {
		p := milterRead(t, c, 'h')
		if !bytes.HasPrefix(p, []byte(name+"\x00")) {
			t.Fatalf("missing spam header %s in %q", name, p)
		}
		if name == "X-SpamGate-Action" && !bytes.Equal(p, []byte("X-SpamGate-Action\x00quarantine\x00")) {
			t.Fatalf("wrong header %q", p)
		}
	}
	milterRead(t, c, 'c')
	got := store.List(1, "")[0]
	if got.MTAAction != "junk_header_requested" || got.Delivery != "" || got.Action != "quarantine" {
		t.Fatalf("wrong disposition %+v", got)
	}
	closePolicyMilter(t, c, done)
}
func TestUntrustedSpamGateHeadersAreStrippedBeforeJunk(t *testing.T) {
	_, c, done := startPolicyMilter(t, "junk", false, nil, milterAddHeader|milterChangeHeader|milterQuarantine)
	policyMessage(t, c, "sample quarantine", true)
	p := milterSend(t, c, 'E', 'm', nil)
	if len(p) < 6 || binary.BigEndian.Uint32(p[:4]) != 1 || string(p[4:]) != "X-SpamGate-Action\x00\x00" {
		t.Fatalf("invalid remove header packet %q", p)
	}
	for _, hdr := range []string{"X-Spam", "X-Spam-Status"} {
		p := milterRead(t, c, 'm')
		if !bytes.Equal(p[4:], []byte(hdr+"\x00\x00")) {
			t.Fatalf("invalid removal of forged %s: %q", hdr, p)
		}
	}
	milterRead(t, c, 'h')
	for i := 0; i < 4; i++ {
		milterRead(t, c, 'h')
	}
	milterRead(t, c, 'c')
	closePolicyMilter(t, c, done)
}
func TestUntrustedSpamGateHeadersFailClosedWithoutModification(t *testing.T) {
	store, c, done := startPolicyMilter(t, "junk", false, nil, milterAddHeader|milterQuarantine)
	policyMessage(t, c, "sample quarantine", true)
	milterSend(t, c, 'E', 't', nil)
	got := store.List(1, "")[0]
	if got.Action != "soft_reject" || got.MTAAction != "smtp_temporary_failure_requested" {
		t.Fatalf("forged header still usable %+v", got)
	}
	closePolicyMilter(t, c, done)
}
func TestOptionalSubjectRewriteRequiresNegotiation(t *testing.T) {
	store, c, done := startPolicyMilter(t, "hold", true, func(cfg *core.Config) {
		cfg.Rules[0].Action = "tag"
	}, milterAddHeader|milterChangeHeader)
	policyMessage(t, c, "sample parcel notice", false)
	milterSend(t, c, 'E', 'h', nil)
	for i := 0; i < 4; i++ {
		milterRead(t, c, 'h')
	}
	changed := milterRead(t, c, 'm')
	if len(changed) < 5 || binary.BigEndian.Uint32(changed[:4]) != 1 || !strings.Contains(string(changed[4:]), "Subject\x00[SPAM] sample parcel notice\x00") {
		t.Fatalf("wrong rewritten subject: %q", changed)
	}
	milterRead(t, c, 'c')
	if got := store.List(1, "")[0]; got.Action != "tag" {
		t.Fatal(got.Action)
	}
	closePolicyMilter(t, c, done)
}
func TestGreylistPolicyProducesTemporaryFailure(t *testing.T) {
	store, c, done := startPolicyMilter(t, "hold", false, func(cfg *core.Config) {
		cfg.Settings.GreylistEnabled = true
		cfg.Settings.GreylistWaitMinutes = 5
		cfg.Rules[0].Action = "tag"
	}, milterAddHeader|milterQuarantine)
	// Genuine Milter CONNECT payload is the only source of remote peer IP.
	milterSend(t, c, 'C', 'c', append([]byte("mx.example\x004\x00\x19"), []byte("198.51.100.99\x00")...))
	policyMessage(t, c, "sample greylist", false)
	milterSend(t, c, 'E', 't', nil)
	got := store.List(1, "")[0]
	if got.Action != "soft_reject" || got.Score == 0 && len(got.Findings) == 0 || got.MTAAction != "smtp_temporary_failure_requested" {
		t.Fatalf("greylist not reflected in record: %+v", got)
	}
	closePolicyMilter(t, c, done)
}
