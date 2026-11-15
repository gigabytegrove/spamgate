package smtpprobe

// failureFinding reports the phase where a read-only SMTP probe stopped.
// It intentionally excludes remote reply text, hostnames, certificate subjects,
// credentials and raw errors, which may contain operator-sensitive data.
func failureFinding(stage string) Finding {
	switch stage {
	case "configuration":
		return Finding{Code: "SMTP_PROBE_CONFIGURATION_FAILED", Severity: "warning", Message: "SMTP diagnostic configuration or cancellation prevented the probe from starting"}
	case "connection":
		return Finding{Code: "SMTP_CONNECTION_FAILED", Severity: "warning", Message: "SMTP diagnostic could not establish a TCP connection; check routing, listener and firewall"}
	case "greeting":
		return Finding{Code: "SMTP_GREETING_FAILED", Severity: "warning", Message: "SMTP diagnostic did not complete an accepted greeting; check listener, protocol framing and timeout"}
	case "ehlo":
		return Finding{Code: "SMTP_EHLO_FAILED", Severity: "warning", Message: "SMTP diagnostic did not complete the initial EHLO exchange; check SMTP protocol and server logs"}
	case "starttls":
		return Finding{Code: "SMTP_STARTTLS_FAILED", Severity: "warning", Message: "SMTP diagnostic could not complete STARTTLS negotiation; check server TLS policy and logs"}
	case "tls_handshake":
		return Finding{Code: "SMTP_TLS_HANDSHAKE_FAILED", Severity: "warning", Message: "SMTP diagnostic could not verify the TLS handshake; check certificate trust, hostname, validity and protocol compatibility"}
	case "post_tls_ehlo":
		return Finding{Code: "SMTP_POST_TLS_EHLO_FAILED", Severity: "warning", Message: "SMTP diagnostic could not complete EHLO over verified TLS; check server logs and post-TLS SMTP policy"}
	default:
		return Finding{Code: "SMTP_PROBE_FAILED", Severity: "warning", Message: "SMTP diagnostic stopped before completion; inspect the sanitized diagnostic error"}
	}
}
