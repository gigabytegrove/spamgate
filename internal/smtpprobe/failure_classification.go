package smtpprobe

import (
 "context"
 "crypto/x509"
 "errors"
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
