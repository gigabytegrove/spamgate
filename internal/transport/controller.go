package transport

// Optional, dedicated controller-style listener. Intentionally separate from
// Rspamd's MTA-facing scan worker and SpamGate's management Web UI. Only the
// explicitly enumerated commands are compatible; unimplemented Rspamd
// controller functions return 404 instead of silently claiming success.

import (
	"context"
	"crypto/subtle"
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

type RspamdController struct {
	ListenAddress string
	Trusted       []*net.IPNet
	Token         string
	Store         *core.Store
}

func ControllerFromEnv(store *core.Store) (*RspamdController, error) {
	addr := strings.TrimSpace(os.Getenv("SPAMGATE_CONTROLLER_LISTEN"))
	if addr == "" {
		return nil, nil
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return nil, errors.New("invalid SPAMGATE_CONTROLLER_LISTEN: use host:port")
	}
	token := os.Getenv("SPAMGATE_CONTROLLER_TOKEN")
	if len(token) < 24 {
		return nil, errors.New("SPAMGATE_CONTROLLER_TOKEN must be at least 24 characters")
	}
	cidrs, err := parseTrustedCIDRs(os.Getenv("SPAMGATE_CONTROLLER_TRUSTED_CIDRS"))
	if err != nil {
		return nil, fmt.Errorf("controller trusted networks: %w", err)
	}
	return &RspamdController{ListenAddress: addr, Trusted: cidrs, Token: token, Store: store}, nil
}
func (s *RspamdController) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "pong\n")
	})
	mux.HandleFunc("GET /actions", func(w http.ResponseWriter, r *http.Request) {
		c := s.Store.Config()
		writeControllerJSON(w, 200, map[string]float64{"reject": c.Settings.RejectThreshold, "add header": c.Settings.TagThreshold, "quarantine": c.Settings.QuarantineThreshold})
	})
	mux.HandleFunc("GET /symbols", func(w http.ResponseWriter, r *http.Request) {
		writeControllerJSON(w, 200, core.ConfiguredSignals(s.Store.Config()))
	})
	mux.HandleFunc("GET /stat", func(w http.ResponseWriter, r *http.Request) {
		writeControllerJSON(w, 200, map[string]any{"messages": s.Store.Stats(""), "bayes": s.Store.BayesStats(), "fuzzy": s.Store.FuzzyStats(), "neural": s.Store.NeuralStats(), "version": core.Version})
	})
	mux.HandleFunc("POST /learnspam", func(w http.ResponseWriter, r *http.Request) { s.train(w, r, "spam") })
	mux.HandleFunc("POST /learnham", func(w http.ResponseWriter, r *http.Request) { s.train(w, r, "ham") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "forbidden", 403)
			return
		}
		peer := net.ParseIP(host)
		allowed := false
		for _, cidr := range s.Trusted {
			if peer != nil && cidr.Contains(peer) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "forbidden", 403)
			return
		}
		// Support Rspamd's conventional Password header as well as Authorization.
		// An explicit controller secret is always required even on trusted networks.
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if provided == "" {
			provided = r.Header.Get("Password")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.Token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if !s.Store.Config().SetupComplete {
			http.Error(w, "setup incomplete", 503)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func writeControllerJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func (s *RspamdController) train(w http.ResponseWriter, r *http.Request, label string) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "sample exceeds 10 MiB", 413)
		return
	}
	stats, err := s.Store.TrainBayes(raw, label)
	if err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	writeControllerJSON(w, 200, map[string]any{"success": true, "classifier": "bayes", "class": label, "stats": stats})
}
func (s *RspamdController) Listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.ListenAddress)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		grace, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(grace)
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
