package smtpprobe

import (
	"context"
 "net"
 "io"
	"strings"
	"testing"
	"time"
)

func TestFailureFindingNeverLeaksRemoteDetails(t *testing.T) {
	for _, stage := range []string{"configuration", "connection", "greeting", "ehlo", "tls_policy", "starttls", "tls_handshake", "post_tls_ehlo", "unknown"} {
		f := failureFinding(stage)
		if f.Code == "" || f.Severity != "warning" || f.Message == "" {
			t.Fatalf("incomplete finding for %q: %+v", stage, f)
		}
		for _, forbidden := range []string{"secret@example.com", "password=", "smtp.internal"} {
			if strings.Contains(f.Message, forbidden) { t.Fatalf("sensitive content in %q: %+v", stage, f) }
		}
	}
}

func TestProbeConfigurationFailureHasStructuredEvidence(t *testing.T) {
	r, err := Probe(context.Background(), Options{Address: "127.0.0.1:25", Timeout: 0})
	if err == nil { t.Fatal("expected invalid timeout") }
	if r.FailureStage != "configuration" || !findingPresent(r.Findings, "SMTP_PROBE_CONFIGURATION_FAILED") {
		t.Fatalf("missing configuration failure evidence: %+v", r)
	}
}

func TestProbeGreetingFailureHasStructuredEvidence(t *testing.T) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
 if listenErr != nil { t.Fatal(listenErr) }
 defer listener.Close()
 go func() { conn, acceptErr := listener.Accept(); if acceptErr == nil { _, _ = io.WriteString(conn, "554 Service unavailable\r\n"); _ = conn.Close() } }()
 addr := listener.Addr().String()
	r, err := Probe(context.Background(), Options{Address: addr, Timeout: time.Second})
	if err == nil { t.Fatal("expected greeting failure") }
	if r.FailureStage != "greeting" || !findingPresent(r.Findings, "SMTP_GREETING_FAILED") {
		t.Fatalf("missing greeting failure evidence: %+v", r)
	}
	if findingPresent(r.Findings, "CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED") {
		t.Fatal("must not infer AUTH policy from failed greeting")
	}
}

func TestProbeTLSRequiredRefusesDowngradeWithEvidence(t *testing.T) {
	addr, _ := server(t, "250 HELP\r\n")
	r, err := Probe(context.Background(), Options{Address: addr, Timeout: time.Second, RequireTLS: true})
	if err == nil { t.Fatal("expected TLS-required refusal") }
	if r.FailureStage != "tls_policy" || !findingPresent(r.Findings, "SMTP_TLS_REQUIRED_UNAVAILABLE") {
		t.Fatalf("missing downgrade refusal evidence: %+v", r)
	}
	if !findingPresent(r.Findings, "STARTTLS_NOT_ADVERTISED") {
		t.Fatalf("missing observed STARTTLS absence: %+v", r)
	}
}
