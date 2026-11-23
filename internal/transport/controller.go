package transport

// Optional, dedicated controller-style listener. Intentionally separate from
// Rspamd's MTA-facing scan worker and SpamGate's management Web UI. Only the
// explicitly enumerated commands are compatible; unimplemented Rspamd
// controller functions return 404 instead of silently claiming success.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

type RspamdController struct {
	ListenAddress string
	Trusted       []*net.IPNet
	Token         string
	Store         *core.Store
	trainingGate controllerTrainingGate
}

func ControllerFromEnv(store *core.Store) (*RspamdController, error) {
	addr := strings.TrimSpace(os.Getenv("SPAMGATE_CONTROLLER_LISTEN"))
	if addr == "" {
		return nil, nil
	}
	if err := validateControllerListenAddress(addr); err != nil {
		return nil, fmt.Errorf("invalid SPAMGATE_CONTROLLER_LISTEN: %w", err)
	}
	token := os.Getenv("SPAMGATE_CONTROLLER_TOKEN")
	if len(token) < 24 || !validControllerToken(token) {
		return nil, errors.New("SPAMGATE_CONTROLLER_TOKEN must be at least 24 printable non-whitespace ASCII characters")
	}
	cidrs, err := parseTrustedCIDRs(os.Getenv("SPAMGATE_CONTROLLER_TRUSTED_CIDRS"))
	if err != nil {
		return nil, fmt.Errorf("controller trusted networks: %w", err)
	}
	return &RspamdController{ListenAddress: addr, Trusted: cidrs, Token: token, Store: store}, nil
}
// validateControllerListenAddress rejects malformed ports before the service starts.
// Port zero is intentionally disallowed for a configured, persistent listener.
func validateControllerListenAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || strings.TrimSpace(host) != host || strings.ContainsAny(host, "\r\n\t") {
		return errors.New("expected host:port")
	}
	if len(port) == 0 {
		return errors.New("port is required")
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return errors.New("port must be numeric")
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
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
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if status := s.controllerAuthorize(r); status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
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
	if !s.trainingGate.acquire() {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "training capacity exhausted", http.StatusTooManyRequests)
		return
	}
	defer s.trainingGate.release()
	raw, status := readControllerTrainingSample(w, r)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return
	}
	stats, err := s.Store.TrainBayes(raw, label)
	if err != nil {
		// Do not disclose classifier internals, corpus contents or filesystem paths to API clients.
		http.Error(w, "training sample rejected", 422)
		return
	}
	writeControllerJSON(w, 200, map[string]any{"success": true, "classifier": "bayes", "class": label, "stats": stats})
}
func (s *RspamdController) Listen(ctx context.Context) error {
	if ctx == nil { return errors.New("controller context is nil") }
	if err := ctx.Err(); err != nil { return err }
	if s == nil { return errors.New("controller is nil") }
	if err := validateControllerListenAddress(s.ListenAddress); err != nil { return err }
	ln, err := net.Listen("tcp", s.ListenAddress)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stopShutdown := context.AfterFunc(ctx, func() {
		grace, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(grace)
	})
	defer stopShutdown()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
