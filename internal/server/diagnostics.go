package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type RelayDiagnostic struct {
	Configured            bool      `json:"configured"`
	Address               string    `json:"address,omitempty"`
	TLSMode               string    `json:"tls_mode,omitempty"`
	TCPReachable          bool      `json:"tcp_reachable"`
	SMTPReady             bool      `json:"smtp_ready"`
	STARTTLSAdvertised    bool      `json:"starttls_advertised"`
	TLSVerified           bool      `json:"tls_verified"`
	AUTHAdvertised        bool      `json:"auth_advertised"`
	CredentialsConfigured bool      `json:"credentials_configured"`
	Detail                string    `json:"detail"`
	CheckedAt             time.Time `json:"checked_at"`
}

// probeRelay performs banner, EHLO and (if configured) certificate-validated
// TLS negotiation. It never attempts AUTH, MAIL FROM, RCPT TO or DATA: even a
// successful probe is not a delivery receipt or proof that credentials work.
func probeRelay(ctx context.Context, addr, tlsMode string, credentialsConfigured bool) RelayDiagnostic {
	result := RelayDiagnostic{Configured: addr != "", Address: addr, TLSMode: tlsMode, CredentialsConfigured: credentialsConfigured, CheckedAt: time.Now().UTC(), Detail: "No relay configured"}
	if addr == "" {
		return result
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		result.Detail = "Invalid relay host:port"
		return result
	}
	if tlsMode == "" {
		tlsMode = "required"
		result.TLSMode = tlsMode
	}
	if tlsMode != "required" && tlsMode != "implicit" && tlsMode != "none" {
		result.Detail = "Invalid TLS mode: configure required, implicit or none"
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 4 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Detail = "TCP connection failed: " + err.Error()
		return result
	}
	defer conn.Close()
	result.TCPReachable = true
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if tlsMode == "implicit" {
		secure := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := secure.HandshakeContext(ctx); err != nil {
			result.Detail = "Implicit TLS handshake/certificate verification failed: " + err.Error()
			return result
		}
		result.TLSVerified = true
		conn = secure
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		result.Detail = "SMTP banner rejected: " + err.Error()
		return result
	}
	defer client.Close()
	if err := client.Hello("spamgate.local"); err != nil {
		result.Detail = "SMTP EHLO failed: " + err.Error()
		return result
	}
	result.SMTPReady = true
	result.STARTTLSAdvertised, _ = client.Extension("STARTTLS")
	if tlsMode == "required" {
		if !result.STARTTLSAdvertised {
			result.SMTPReady = false
			result.Detail = "SMTP server does not advertise required STARTTLS"
			return result
		}
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			result.SMTPReady = false
			result.Detail = "STARTTLS handshake/certificate verification failed: " + err.Error()
			return result
		}
		result.TLSVerified = true
	}
	result.AUTHAdvertised, _ = client.Extension("AUTH")
	if credentialsConfigured && !result.AUTHAdvertised {
		result.Detail = "SMTP negotiation succeeded but the server does not advertise AUTH; no credentials were sent"
	} else {
		result.Detail = fmt.Sprintf("SMTP banner and EHLO succeeded; TLS mode %s; encrypted channel verified=%t; AUTH advertised=%t. No authentication or delivery was attempted", tlsMode, result.TLSVerified, result.AUTHAdvertised)
	}
	_ = client.Quit()
	return result
}

func (s *Server) integrationDiagnostics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	addr := strings.TrimSpace(os.Getenv("SPAMGATE_RELAY_ADDRESS"))
	result := probeRelay(r.Context(), addr, os.Getenv("SPAMGATE_RELAY_TLS"), os.Getenv("SPAMGATE_RELAY_USERNAME") != "")
	jsonReply(w, http.StatusOK, map[string]any{"relay": result, "services": s.Runtime.Services, "note": "SMTP checks do not authenticate, send a message, or verify mail-server disposition. Listener settings are configuration, not proof of MTA interoperability."})
}
