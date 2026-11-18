package smtpprobe

import (
 "context"
 "crypto/x509"
 "errors"
 "fmt"
 "net"
 "os"
 "syscall"
)

// classifyProbeFailure exposes stable, non-sensitive failure categories.
// Do not include raw peer replies, DNS names, or certificate subjects in JSON.
func classifyProbeFailure(stage string, err error) string {
 if err == nil { return "" }
 if errors.Is(err, context.Canceled) { return "CANCELED" }
 if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) { return "TIMEOUT" }
 var netErr net.Error
 if errors.As(err, &netErr) && netErr.Timeout() { return "TIMEOUT" }
 var reply *SMTPReplyError
 if errors.As(err, &reply) {
  if reply.Code >= 400 && reply.Code < 500 { return "SMTP_TEMPORARY_REJECTION" }
  if reply.Code >= 500 && reply.Code < 600 { return "SMTP_PERMANENT_REJECTION" }
  return "SMTP_UNEXPECTED_REPLY"
 }
 if stage == "connection" {
  var dnsErr *net.DNSError
  if errors.As(err, &dnsErr) { return "DNS_LOOKUP_FAILED" }
  if errors.Is(err, syscall.ECONNREFUSED) { return "CONNECTION_REFUSED" }
  return "TCP_CONNECT_FAILED"
 }
 if stage == "tls_handshake" {
  var unknown x509.UnknownAuthorityError
  if errors.As(err, &unknown) { return "TLS_UNKNOWN_AUTHORITY" }
  var hostname x509.HostnameError
  if errors.As(err, &hostname) { return "TLS_HOSTNAME_MISMATCH" }
  var invalid x509.CertificateInvalidError
  if errors.As(err, &invalid) {
   if invalid.Reason == x509.Expired { return "TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID" }
   return "TLS_CERTIFICATE_INVALID"
  }
  return "TLS_HANDSHAKE_FAILED"
 }
 switch stage {
 case "configuration": return "INVALID_CONFIGURATION"
 case "greeting": return "SMTP_GREETING_FAILED"
 case "ehlo": return "SMTP_EHLO_FAILED"
 case "tls_policy": return "TLS_REQUIRED_UNAVAILABLE"
 case "starttls": return "STARTTLS_NEGOTIATION_FAILED"
 case "post_tls_ehlo": return "POST_TLS_EHLO_FAILED"
 default: return "SMTP_PROBE_FAILED"
 }
}

func classifiedFailureFinding(kind string) *Finding {
 var message string
 switch kind {
 case "SMTP_TEMPORARY_REJECTION": message = "SMTP peer returned a temporary 4xx response; inspect service availability and retry policy"
 case "SMTP_PERMANENT_REJECTION": message = "SMTP peer returned a permanent 5xx response; inspect greeting, EHLO and TLS service policy"
 case "SMTP_UNEXPECTED_REPLY": message = "SMTP peer returned an unexpected response code for the protocol stage"
 case "TIMEOUT": message = "SMTP diagnostic timed out; inspect network latency, listener responsiveness and firewall timeouts"
 case "DNS_LOOKUP_FAILED": message = "SMTP target could not be resolved; inspect resolver availability and DNS records"
 case "CONNECTION_REFUSED": message = "SMTP TCP connection was refused; inspect listener address, service status and firewall policy"
 case "TLS_UNKNOWN_AUTHORITY": message = "SMTP TLS certificate chain is not trusted by the diagnostic host"
 case "TLS_HOSTNAME_MISMATCH": message = "SMTP TLS certificate does not match the configured server name"
 case "TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID": message = "SMTP TLS certificate validity period does not include the diagnostic time"
 case "TLS_CERTIFICATE_INVALID": message = "SMTP TLS certificate failed X.509 validation"
 default: return nil
 }
 return &Finding{Code: "SMTP_" + kind, Severity: "warning", Message: message}
}

// SMTPReplyError contains only a numeric status and a fixed local stage.
// Peer-supplied text must never enter diagnostics or operator logs.
type SMTPReplyError struct { Stage string; Code int }
func (e *SMTPReplyError) Error() string {
 if e == nil { return "SMTP unexpected response" }
 return fmt.Sprintf("SMTP %s rejected with status %d", e.Stage, e.Code)
}
