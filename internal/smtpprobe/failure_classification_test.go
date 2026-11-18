package smtpprobe

import (
 "context"
 "crypto/x509"
 "errors"
 "fmt"
 "net"
 "strings"
 "syscall"
 "testing"
)

func TestClassifyProbeFailure(t *testing.T) {
 tests := []struct {
  name, stage, want string
  err error
 }{
  {"cancel", "connection", "CANCELED", context.Canceled},
  {"deadline", "greeting", "TIMEOUT", context.DeadlineExceeded},
  {"dns", "connection", "DNS_LOOKUP_FAILED", &net.DNSError{Err:"no such host", Name:"private.example"}},
  {"refused", "connection", "CONNECTION_REFUSED", &net.OpError{Op:"dial", Net:"tcp", Err:syscall.ECONNREFUSED}},
  {"tcp", "connection", "TCP_CONNECT_FAILED", errors.New("unreachable")},
  {"authority", "tls_handshake", "TLS_UNKNOWN_AUTHORITY", x509.UnknownAuthorityError{}},
  {"hostname", "tls_handshake", "TLS_HOSTNAME_MISMATCH", x509.HostnameError{Host:"private.example"}},
  {"expired", "tls_handshake", "TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID", x509.CertificateInvalidError{Reason:x509.Expired}},
  {"invalid", "tls_handshake", "TLS_CERTIFICATE_INVALID", x509.CertificateInvalidError{Reason:x509.NotAuthorizedToSign}},
  {"tls", "tls_handshake", "TLS_HANDSHAKE_FAILED", errors.New("unsupported protocol")},
  {"tls policy", "tls_policy", "TLS_REQUIRED_UNAVAILABLE", errors.New("no STARTTLS")},
  {"post tls", "post_tls_ehlo", "POST_TLS_EHLO_FAILED", errors.New("invalid reply")},
 }
 for _, tt := range tests {
  t.Run(tt.name, func(t *testing.T) {
   if got := classifyProbeFailure(tt.stage, fmt.Errorf("wrapped: %w", tt.err)); got != tt.want {
    t.Fatalf("got %q, want %q", got, tt.want)
   }
  })
 }
 if got := classifyProbeFailure("connection", nil); got != "" { t.Fatalf("nil error: %q", got) }
}

func TestClassifiedFailureFindingSanitizesEvidence(t *testing.T) {
 for _, kind := range []string{"TIMEOUT", "DNS_LOOKUP_FAILED", "CONNECTION_REFUSED", "TLS_UNKNOWN_AUTHORITY", "TLS_HOSTNAME_MISMATCH", "TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID", "TLS_CERTIFICATE_INVALID"} {
  finding := classifiedFailureFinding(kind)
  if finding == nil || finding.Code != "SMTP_"+kind || finding.Severity != "warning" { t.Fatalf("%s: %+v", kind, finding) }
  if strings.Contains(finding.Message, "private.example") { t.Fatalf("sensitive name leaked: %+v", finding) }
 }
 if classifiedFailureFinding("CANCELED") != nil { t.Fatal("cancellation must not create an operator alert") }
 if classifiedFailureFinding("UNKNOWN") != nil { t.Fatal("unknown categories must not create invented alerts") }
}

func TestProbeFailureCategoryExposed(t *testing.T) {
 result, err := Probe(context.Background(), Options{Timeout:0})
 if err == nil || result.FailureStage != "configuration" || result.FailureKind != "INVALID_CONFIGURATION" {
  t.Fatalf("result=%+v err=%v", result, err)
 }
}
