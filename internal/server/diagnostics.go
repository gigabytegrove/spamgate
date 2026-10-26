package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"
)

type RelayDiagnostic struct {
	Configured   bool      `json:"configured"`
	Address      string    `json:"address,omitempty"`
	TCPReachable bool      `json:"tcp_reachable"`
	Detail       string    `json:"detail"`
	CheckedAt    time.Time `json:"checked_at"`
}

// This is a network reachability probe, not a successful SMTP/TLS/Auth
// handshake or delivery certification. No customer message is transmitted.
func (s *Server) integrationDiagnostics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	addr := os.Getenv("SPAMGATE_RELAY_ADDRESS")
	result := RelayDiagnostic{Configured: addr != "", Address: addr, CheckedAt: time.Now().UTC(), Detail: "No relay configured"}
	if addr != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			result.Detail = "TCP connect failed: " + err.Error()
		} else {
			result.TCPReachable = true
			result.Detail = "TCP reachable (SMTP/TLS/authentication not yet tested)"
			_ = conn.Close()
		}
	}
	jsonReply(w, http.StatusOK, map[string]any{"relay": result, "services": s.Runtime.Services, "note": "Listener values indicate configuration only, not verified MTA interoperability."})
}
