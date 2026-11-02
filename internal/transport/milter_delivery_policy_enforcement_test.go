package transport

import (
    "context"
    "encoding/binary"
    "net"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// These tests exercise the actual Milter wire reply, not merely the stored
// intended MTAAction. A previous bug persisted a temporary-failure request
// but sent SMFIR_CONTINUE, silently accepting rate-limited mail.
func newPolicyMilterWire(t *testing.T, store *core.Store) (net.Conn, <-chan error) {
    t.Helper()
    m := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
    client, server := net.Pipe()
    done := make(chan error, 1)
    go func() {
        defer server.Close()
        done <- m.handle(context.Background(), server)
    }()
    t.Cleanup(func() { _ = client.Close() })
    opts := make([]byte, 12)
    binary.BigEndian.PutUint32(opts[:4], 6)
    binary.BigEndian.PutUint32(opts[4:8], milterAddHeader|milterQuarantine)
    milterSend(t, client, 'O', 'O', opts)
    milterSend(t, client, 'C', 'c', []byte("mx.example\x004\x00\x19"+"8.8.8.8\x00"))
    return client, done
}

func policyMilterMessage(t *testing.T, conn net.Conn, subject, body string, want byte) {
    t.Helper()
    milterSend(t, conn, 'M', 'c', []byte("<sender@example.org>\x00"))
    milterSend(t, conn, 'R', 'c', []byte("<recipient@example.net>\x00"))
    milterSend(t, conn, 'L', 'c', []byte("From\x00sender@example.org\x00"))
    milterSend(t, conn, 'L', 'c', []byte("Subject\x00"+subject+"\x00"))
    milterSend(t, conn, 'N', 'c', nil)
    milterSend(t, conn, 'B', 'c', []byte(body))
    milterSend(t, conn, 'E', want, nil)
}

func finishPolicyMilter(t *testing.T, conn net.Conn, done <-chan error) {
    t.Helper()
    milterSend(t, conn, 'Q', 0, nil)
    select {
    case err := <-done:
        if err != nil { t.Fatalf("milter exited with error: %v", err) }
    case <-time.After(5*time.Second):
        t.Fatal("milter failed to exit")
    }
}

func TestMilterRateLimitSendsRealSMTPTempfailAndPersistsEvidence(t *testing.T) {
    store, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    if err := store.UpdateConfig(func(c *core.Config) error {
        c.SetupComplete = true
        c.Settings.TagThreshold = 100
        c.Settings.QuarantineThreshold = 200
        c.Settings.RejectThreshold = 1000
        c.Settings.RateLimitEnabled = true
        c.Settings.RateLimitPerHour = 10
        return nil
    }); err != nil { t.Fatal(err) }
    conn, done := newPolicyMilterWire(t, store)
    for i := 0; i < 10; i++ {
        policyMilterMessage(t, conn, "Routine status report", "Routine status report\r\n", 'c')
    }
    policyMilterMessage(t, conn, "Routine status report", "Routine status report\r\n", 't')
    events := store.List(20, "")
    if len(events) != 11 { t.Fatalf("expected eleven recorded SMTP decisions, got %d", len(events)) }
    last := events[0]
    if last.Action != "soft_reject" || last.MTAAction != "smtp_temporary_failure_requested" || last.MTAActionState != "requested" {
        t.Fatalf("persisted MTA action does not match tempfail wire response: %+v", last)
    }
    // A rejected attempt must not erase the allowance evidence; repeated
    // attempts must remain deferred rather than resetting the rate counter.
    policyMilterMessage(t, conn, "Routine status report", "Routine status report\r\n", 't')
    finishPolicyMilter(t, conn, done)
}

// The store directory is deliberately held by the caller, not inferred from
// private Store fields.
func TestMilterRateLimitSurvivesWorkerRestart(t *testing.T) {
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    if err := store.UpdateConfig(func(c *core.Config) error {
        c.SetupComplete = true
        c.Settings.TagThreshold = 100
        c.Settings.QuarantineThreshold = 200
        c.Settings.RejectThreshold = 1000
        c.Settings.RateLimitEnabled = true
        c.Settings.RateLimitPerHour = 10
        return nil
    }); err != nil { t.Fatal(err) }
    first, firstDone := newPolicyMilterWire(t, store)
    for i := 0; i < 10; i++ {
        policyMilterMessage(t, first, "Routine status report", "Routine status report\r\n", 'c')
    }
    finishPolicyMilter(t, first, firstDone)
    restarted, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    second, secondDone := newPolicyMilterWire(t, restarted)
    policyMilterMessage(t, second, "Routine status report", "Routine status report\r\n", 't')
    events := restarted.List(20, "")
    if len(events) != 11 || events[0].MTAAction != "smtp_temporary_failure_requested" {
        t.Fatalf("restart bypassed persisted rate limit: %+v", events)
    }
    finishPolicyMilter(t, second, secondDone)
}

func TestMilterPolicyPersistenceFailureTempfailsWithoutRecordingVerdict(t *testing.T) {
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    if err := store.UpdateConfig(func(c *core.Config) error {
        c.SetupComplete = true
        c.Settings.TagThreshold = 100
        c.Settings.QuarantineThreshold = 200
        c.Settings.RejectThreshold = 1000
        c.Settings.RateLimitEnabled = true
        c.Settings.RateLimitPerHour = 10
        return nil
    }); err != nil { t.Fatal(err) }
    path := filepath.Join(dir, "delivery-policy.json")
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    conn, done := newPolicyMilterWire(t, store)
    policyMilterMessage(t, conn, "Routine status report", "Routine status report\r\n", 't')
    if got := store.List(10, ""); len(got) != 0 {
        t.Fatalf("failed policy persistence recorded verdict: %+v", got)
    }
    if err := os.Remove(path); err != nil { t.Fatal(err) }
    policyMilterMessage(t, conn, "Routine status report", "Routine status report\r\n", 'c')
    if got := store.List(10, ""); len(got) != 1 || got[0].MTAAction != "continue_requested" {
        t.Fatalf("healthy recovery did not accept and record: %+v", got)
    }
    finishPolicyMilter(t, conn, done)
}
