package transport

// Compatibility HTTP worker for the Rspamd v2 scanning protocol. It deliberately
// uses a separate network listener from the administrative console: an MTA's
// trusted-peer policy must never grant access to account-management endpoints.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

type RspamdWorker struct {
	ListenAddress string
	Trusted       []*net.IPNet
	Token         string
	Scanner       *core.Scanner
	Store         *core.Store
}

func parseTrustedCIDRs(raw string) ([]*net.IPNet, error) {
 return parseRspamdTrustedNetworks(raw)
}
func RspamdFromEnv(store *core.Store) (*RspamdWorker, error) {
	addr := strings.TrimSpace(os.Getenv("SPAMGATE_RSPAMD_LISTEN"))
	if addr == "" {
		return nil, nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return nil, fmt.Errorf("invalid SPAMGATE_RSPAMD_LISTEN: use host:port")
	}
	trusted := os.Getenv("SPAMGATE_RSPAMD_TRUSTED_CIDRS")
	if trusted == "" {
		trusted = "127.0.0.1/32,::1/128"
	}
	cidrs, err := parseTrustedCIDRs(trusted)
	if err != nil {
		return nil, err
	}
	return &RspamdWorker{ListenAddress: addr, Trusted: cidrs, Token: os.Getenv("SPAMGATE_RSPAMD_TOKEN"), Scanner: &core.Scanner{Store: store}, Store: store}, nil
}
func (s *RspamdWorker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "pong\n")
	})
	for _, p := range []string{"/checkv2", "/check", "/symbols", "/scanv2"} {
		mux.HandleFunc("POST "+p, s.check)
	}
	mux.HandleFunc("POST /checkv3", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "protocol v3 is not supported; use /checkv2", http.StatusNotImplemented)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		allowed := rspamdPeerTrusted(r.RemoteAddr, s.Trusted)
		if !allowed {
			http.Error(w, "forbidden", 403)
			return
		}
		if s.Token != "" {
			if !rspamdBearerAuthorized(r.Header.Values("Authorization"), s.Token) {
				http.Error(w, "unauthorized", 401)
				return
			}
		}
		if r.URL.Path != "/ping" && !s.Store.Config().SetupComplete {
			http.Error(w, "SpamGate setup incomplete", 503)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *RspamdWorker) check(w http.ResponseWriter, r *http.Request) {
	metadata, metadataErr := rspamdReadRequestMetadata(r.Header)
	if metadataErr != nil {
		http.Error(w, "invalid request metadata: "+metadataErr.Error(), http.StatusBadRequest)
		return
	}
	flags, flagsErr := rspamdParseFlags(metadata.Flags)
	if flagsErr != nil {
		http.Error(w, flagsErr.Error(), http.StatusUnprocessableEntity)
		return
	}
	validatedHelo, preflightErr := rspamdValidateRequestPreflight(metadata)
	if preflightErr != nil {
		status := rspamdPreflightHTTPStatus(preflightErr)
		http.Error(w, preflightErr.Error(), status)
		return
	}
	clientIP, validClientIP := rspamdClientIP(metadata.ClientIP)
	if !validClientIP {
		http.Error(w, "invalid IP header", http.StatusBadRequest)
		return
	}
	if r.ContentLength > 10<<20 {
		http.Error(w, "message exceeds 10 MiB", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var limitErr *http.MaxBytesError
		if errors.As(err, &limitErr) {
			http.Error(w, "message exceeds 10 MiB", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "message body could not be read", http.StatusBadRequest)
		}
		return
	}
	recipients := metadata.Recipients
	msg, err := s.Scanner.Scan(r.Context(), core.Input{Raw: raw, Sender: metadata.Sender, Recipients: recipients, ClientIP: clientIP, Helo: validatedHelo, Connector: "rspamd-http"})
	if err != nil {
		http.Error(w, "message scan failed", http.StatusUnprocessableEntity)
		return
	}
	if !flags["no_log"] {
		if err := s.Store.Save(msg); err != nil {
			http.Error(w, "history persistence failed", 503)
			return
		}
	}
	cfg := s.Store.Config()
	symbols := map[string]map[string]any{}
	for _, f := range msg.Findings {
		if cur, ok := symbols[f.Symbol]; ok {
			cur["score"] = cur["score"].(float64) + f.Score
			cur["options"] = append(cur["options"].([]string), f.Detail)
		} else {
			symbols[f.Symbol] = map[string]any{"name": f.Symbol, "score": f.Score, "options": []string{f.Detail}, "description": f.Source}
		}
	}
	action := "no action"
	switch msg.Action {
	case "tag":
		action = "add header"
	case "reject":
		action = "reject"
	case "quarantine":
		action = "quarantine"
	}
	reply := map[string]any{"is_skipped": false, "score": msg.Score, "required_score": cfg.Settings.RejectThreshold, "action": action, "symbols": symbols, "message-id": msg.MessageID, "thresholds": map[string]float64{"reject": cfg.Settings.RejectThreshold, "add header": cfg.Settings.TagThreshold, "quarantine": cfg.Settings.QuarantineThreshold}, "scan_id": msg.ID}
	if action == "add header" {
		reply["milter"] = map[string]any{"add_headers": map[string]any{"X-Spam": map[string]any{"value": "Yes", "order": 0}}}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(reply)
}
func (s *RspamdWorker) Listen(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.ListenAddress)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		case <-done:
			return
		}
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
