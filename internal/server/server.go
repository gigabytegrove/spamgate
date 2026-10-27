package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/hostinspect"
	"github.com/gigabytegrove/spamgate/internal/transport"
)

type Identity struct {
	Name    string `json:"name"`
	Email   string `json:"email,omitempty"`
	Role    string `json:"role"`
	Session bool   `json:"session"`
	CSRF    string `json:"csrf,omitempty"`
}
type session struct {
	Identity Identity
	Expires  time.Time
}
type throttle struct {
	Failures int
	Until    time.Time
}

// RuntimeService reports local listener configuration, not remote delivery health.
type RuntimeService struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address,omitempty"`
	Detail  string `json:"detail"`
}

type RuntimeStatus struct {
	Services        map[string]RuntimeService `json:"services"`
	RelayConfigured bool                      `json:"relay_configured"`
}

type Server struct {
	Queue      *transport.DeliveryQueue
	Store      *core.Store
	Runtime    RuntimeStatus
	Scanner    *core.Scanner
	Deliver    func(context.Context, core.Message, []byte) error
	sessions   map[string]session
	throttles  map[string]throttle
	mu         sync.Mutex
	secure     bool
	setupToken string
	log        *slog.Logger
}

func New(store *core.Store, deliver func(context.Context, core.Message, []byte) error) *Server {
	s := &Server{Store: store, Scanner: &core.Scanner{Store: store}, Deliver: deliver, sessions: map[string]session{}, throttles: map[string]throttle{}, secure: os.Getenv("SPAMGATE_SECURE_COOKIES") == "true", log: slog.Default()}
	if !store.Config().SetupComplete {
		s.setupToken = randomString()
		s.log.Warn("First-run setup requires this one-time claim key. Protect your logs.", "setup_key", s.setupToken)
	}
	return s
}

// SetupClaimKey is for the local Windows first-run dialog only; the HTTP API
// never exposes this secret and service-mode processes never display it.
func (s *Server) SetupClaimKey() string { return s.setupToken }

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	jsonReply(w, status, map[string]string{"error": msg})
}
func decode(r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var tail any
	if e := d.Decode(&tail); e != io.EOF {
		return errors.New("extra JSON content")
	}
	return nil
}
func randomString() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return host
}
func isSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, e := url.Parse(origin)
	if e != nil {
		return false
	}
	return parsed.Host == r.Host && (parsed.Scheme == "https" || parsed.Scheme == "http")
}
func (s *Server) current(r *http.Request) (Identity, bool) {
	if cookie, e := r.Cookie("spamgate_session"); e == nil {
		s.mu.Lock()
		ss, ok := s.sessions[cookie.Value]
		if ok && time.Now().After(ss.Expires) {
			delete(s.sessions, cookie.Value)
			ok = false
		}
		s.mu.Unlock()
		if ok {
			for _, u := range s.Store.Config().Users {
				if u.Name == ss.Identity.Name && u.Role == ss.Identity.Role {
					return ss.Identity, true
				}
			}
			s.mu.Lock()
			delete(s.sessions, cookie.Value)
			s.mu.Unlock()
		}
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		token := strings.TrimPrefix(h, "Bearer ")
		for _, t := range s.Store.Config().Tokens {
			if core.CheckToken(token, t) {
				return Identity{Name: t.Name, Role: t.Scope}, true
			}
		}
	}
	return Identity{}, false
}
func (s *Server) authorized(w http.ResponseWriter, r *http.Request, admin bool, mutating bool) (Identity, bool) {
	cfg := s.Store.Config()
	if !cfg.SetupComplete {
		fail(w, 503, "Complete first-run setup")
		return Identity{}, false
	}
	id, ok := s.current(r)
	if !ok {
		fail(w, 401, "Authentication required")
		return id, false
	}
	if admin && id.Role != "admin" {
		fail(w, 403, "Administrator access required")
		return id, false
	}
	if mutating && id.Session {
		if !isSameOrigin(r) || r.Header.Get("X-CSRF-Token") == "" || r.Header.Get("X-CSRF-Token") != id.CSRF {
			fail(w, 403, "Invalid CSRF token or origin")
			return id, false
		}
	}
	return id, true
}
func (s *Server) Router() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, map[string]any{"status": "ok", "version": core.Version})
	})
	m.HandleFunc("GET /", s.index)
	m.HandleFunc("GET /assets/app.css", assetCSS)
	m.HandleFunc("GET /assets/app.js", assetJS)
	m.HandleFunc("GET /api/v1/status", s.status)
	m.HandleFunc("POST /api/v1/setup", s.setup)
	m.HandleFunc("POST /api/v1/login", s.login)
	m.HandleFunc("POST /api/v1/logout", s.logout)
	m.HandleFunc("GET /api/v1/me", s.me)
	m.HandleFunc("POST /api/v1/scan", s.scan)
	m.HandleFunc("POST /api/v1/scan/simulate", s.simulateScan)
	m.HandleFunc("GET /api/v1/messages", s.messages)
	m.HandleFunc("GET /api/v1/history/search", s.searchHistory)
	m.HandleFunc("GET /api/v1/messages/{id}/preview", s.quarantinePreview)

	m.HandleFunc("GET /api/v1/messages/{id}", s.message)
	m.HandleFunc("POST /api/v1/messages/{id}/override", s.override)
	m.HandleFunc("POST /api/v1/messages/{id}/release", s.release)
	m.HandleFunc("DELETE /api/v1/messages/{id}/quarantine", s.discardQuarantine)
	m.HandleFunc("GET /api/v1/statistics", s.stats)
	m.HandleFunc("GET /api/v1/runtime", s.runtime)
	m.HandleFunc("GET /api/v1/host", s.hostReport)
	m.HandleFunc("GET /api/v1/integrations/diagnostics", s.integrationDiagnostics)
	m.HandleFunc("GET /api/v1/delivery-queue", s.deliveryQueue)
	m.HandleFunc("GET /api/v1/metrics", s.metrics)
	m.HandleFunc("POST /api/v1/delivery-queue/{id}/retry", s.retryDelivery)
	m.HandleFunc("DELETE /api/v1/delivery-queue/{id}", s.discardDelivery)
	m.HandleFunc("GET /api/v1/export", s.export)
	m.HandleFunc("GET /api/v1/config", s.config)
	m.HandleFunc("GET /api/v1/signals", s.signals)
	m.HandleFunc("GET /api/v1/bayes/stats", s.bayesStats)
	m.HandleFunc("POST /api/v1/bayes/train", s.bayesTrain)
	m.HandleFunc("GET /api/v1/fuzzy/stats", s.fuzzyStats)
	m.HandleFunc("GET /api/v1/fuzzy/entries", s.fuzzyEntries)
	m.HandleFunc("POST /api/v1/fuzzy/train", s.fuzzyTrain)
	m.HandleFunc("DELETE /api/v1/fuzzy/entries/{id}", s.fuzzyDelete)
	m.HandleFunc("GET /api/v1/neural/stats", s.neuralStats)
	m.HandleFunc("POST /api/v1/neural/train/{id}", s.neuralTrain)
	m.HandleFunc("PUT /api/v1/signals/{symbol}", s.updateSignal)
	m.HandleFunc("PUT /api/v1/settings", s.settings)
	m.HandleFunc("POST /api/v1/rules", s.addRule)
	m.HandleFunc("PUT /api/v1/rules/{id}", s.updateRule)
	m.HandleFunc("DELETE /api/v1/rules/{id}", s.deleteRule)
	m.HandleFunc("POST /api/v1/users", s.addUser)
	m.HandleFunc("DELETE /api/v1/users/{name}", s.deleteUser)
	m.HandleFunc("POST /api/v1/tokens", s.addToken)
	m.HandleFunc("DELETE /api/v1/tokens/{name}", s.deleteToken)
	m.HandleFunc("POST /api/v1/dns-lists", s.addDNSList)
	m.HandleFunc("DELETE /api/v1/dns-lists/{zone}", s.deleteDNSList)
	return securityHeaders(m)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			if !isSameOrigin(r) {
				fail(w, 403, "Cross-origin request denied")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Config()
	jsonReply(w, 200, map[string]any{"configured": cfg.SetupComplete, "version": core.Version, "product": "SpamGate"})
}
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		SiteName string `json:"site_name"`
		SetupKey string `json:"setup_key"`
	}
	if e := decode(r, &in); e != nil {
		fail(w, 400, "Invalid setup request")
		return
	}
	if s.setupToken == "" || subtle.ConstantTimeCompare([]byte(in.SetupKey), []byte(s.setupToken)) != 1 {
		fail(w, 403, "Invalid setup claim key; see container logs")
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if len(in.Username) < 3 || len(in.Username) > 48 || strings.ContainsAny(in.Username, " @:/\\") {
		fail(w, 400, "Username must be 3–48 characters without spaces")
		return
	}
	if len(in.SiteName) < 2 || len(in.SiteName) > 80 {
		fail(w, 400, "Site name must be 2–80 characters")
		return
	}
	salt, hash, e := core.MakePassword(in.Password)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	e = s.Store.UpdateConfig(func(c *core.Config) error {
		if c.SetupComplete {
			return errors.New("setup already completed")
		}
		c.Settings.SiteName = in.SiteName
		c.Users = []core.User{{Name: in.Username, Role: "admin", Salt: salt, PasswordHash: hash}}
		c.SetupComplete = true
		return nil
	})
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	s.setupToken = ""
	s.newSession(w, Identity{Name: in.Username, Role: "admin"})
	jsonReply(w, 201, map[string]string{"status": "configured"})
}
func (s *Server) newSession(w http.ResponseWriter, id Identity) {
	v := randomString()
	id.Session = true
	id.CSRF = randomString()
	s.mu.Lock()
	s.sessions[v] = session{Identity: id, Expires: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "spamgate_session", Value: v, Path: "/", MaxAge: 43200, Secure: s.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e := decode(r, &in); e != nil {
		fail(w, 400, "Invalid login request")
		return
	}
	ip := clientIP(r)
	s.mu.Lock()
	a := s.throttles[ip]
	locked := time.Now().Before(a.Until)
	s.mu.Unlock()
	if locked {
		fail(w, 429, "Too many attempts. Try again later.")
		return
	}
	var user core.User
	found := false
	for _, u := range s.Store.Config().Users {
		if strings.EqualFold(in.Username, u.Name) {
			user = u
			found = true
			break
		}
	}
	if !found || !core.CheckPassword(in.Password, user) {
		s.mu.Lock()
		a = s.throttles[ip]
		a.Failures++
		if a.Failures >= 5 {
			a.Until = time.Now().Add(5 * time.Minute)
			a.Failures = 0
		}
		s.throttles[ip] = a
		s.mu.Unlock()
		fail(w, 401, "Invalid username or password")
		return
	}
	s.mu.Lock()
	delete(s.throttles, ip)
	s.mu.Unlock()
	s.newSession(w, Identity{Name: user.Name, Email: user.Email, Role: user.Role})
	jsonReply(w, 200, map[string]string{"status": "authenticated"})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, true)
	if !ok {
		return
	}
	_ = id
	if c, e := r.Cookie("spamgate_session"); e == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "spamgate_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	jsonReply(w, 200, id)
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, true)
	if !ok {
		return
	}
	if !id.Session && id.Role != "scan" && id.Role != "admin" {
		fail(w, 403, "Scan token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		fail(w, 413, "Message exceeds 10 MiB")
		return
	}
	recipients := strings.Split(r.Header.Get("X-SpamGate-Recipients"), ",")
	clean := []string{}
	for _, x := range recipients {
		if v := strings.TrimSpace(x); v != "" {
			clean = append(clean, v)
		}
	}
	client := r.Header.Get("X-SpamGate-Client-IP")
	if client != "" && net.ParseIP(client) == nil {
		fail(w, 400, "Invalid client IP")
		return
	}
	m, e := s.Scanner.Scan(r.Context(), core.Input{Raw: raw, Sender: r.Header.Get("X-SpamGate-Sender"), Recipients: clean, ClientIP: client, Connector: "http"})
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if e = s.Store.Save(m); e != nil {
		s.log.Error("save scan", "error", e)
		fail(w, 503, "Persistence failure")
		return
	}
	jsonReply(w, 200, m)
}
func (s *Server) messages(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	email := ""
	if id.Role != "admin" {
		email = id.Email
		if email == "" {
			fail(w, 403, "No mailbox is assigned to this account")
			return
		}
	}
	limit := 100
	if n, e := strconv.Atoi(r.URL.Query().Get("limit")); e == nil && n > 0 && n <= 1000 {
		limit = n
	}
	out := s.Store.List(limit, email)
	if id.Role != "admin" {
		for i := range out {
			out[i].Recipients = []string{id.Email}
		}
	}
	jsonReply(w, 200, out)
}
func (s *Server) message(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	m, found := s.Store.Get(r.PathValue("id"))
	if !found {
		fail(w, 404, "Message not found")
		return
	}
	if id.Role != "admin" && !hasEmail(m.Recipients, id.Email) {
		fail(w, 403, "Not your mailbox")
		return
	}
	if id.Role != "admin" {
		m.Recipients = []string{id.Email}
	}
	jsonReply(w, 200, m)
}
func hasEmail(xs []string, value string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, value) && value != "" {
			return true
		}
	}
	return false
}
func (s *Server) hostReport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	jsonReply(w, http.StatusOK, hostinspect.Detect(r.Context()))
}

func (s *Server) runtime(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	jsonReply(w, http.StatusOK, s.Runtime)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	email := ""
	if id.Role != "admin" {
		email = id.Email
		if email == "" {
			fail(w, 403, "No mailbox is assigned to this account")
			return
		}
	}
	jsonReply(w, 200, s.Store.Stats(email))
}
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, false)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=spamgate-history.jsonl")
	w.Header().Set("Cache-Control", "no-store")
	if e := s.Store.Export(w); e != nil {
		s.log.Error("export", "error", e)
	}
}
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	c := s.Store.Config()
	for i := range c.Users {
		c.Users[i].Salt = ""
		c.Users[i].PasswordHash = ""
	}
	for i := range c.Tokens {
		c.Tokens[i].Hash = ""
	}
	if id.Role != "admin" {
		rules := []core.Rule{}
		for _, rule := range c.Rules {
			if strings.EqualFold(rule.Owner, id.Email) && id.Email != "" {
				rules = append(rules, rule)
			}
		}
		c.Rules = rules
		c.Users = nil
		c.Tokens = nil
		c.DNSLists = nil
	}
	jsonReply(w, 200, c)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	var in core.Settings
	if e := decode(r, &in); e != nil || !in.Valid() {
		fail(w, 400, "Invalid settings; thresholds must increase: tag < quarantine < reject")
		return
	}
	e := s.Store.UpdateConfig(func(c *core.Config) error { c.Settings = in; return nil })
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	jsonReply(w, 200, in)
}
func validRule(r core.Rule) error {
	kinds := map[string]bool{"sender_email": true, "sender_domain": true, "recipient_email": true, "client_ip": true, "subject_contains": true, "body_contains": true, "url_domain": true, "header_contains": true}
	if !kinds[r.Kind] || len(r.Name) < 2 || len(r.Name) > 100 || len(r.Value) < 1 || len(r.Value) > 256 || r.Score < -100 || r.Score > 100 {
		return errors.New("invalid rule type, name, value or score")
	}
	if r.Action != "" && r.Action != "accept" && r.Action != "tag" && r.Action != "quarantine" && r.Action != "reject" {
		return errors.New("invalid forced action")
	}
	if r.Priority < -1000 || r.Priority > 1000 || (!r.ExpiresAt.IsZero() && r.ExpiresAt.Before(time.Now())) {
		return errors.New("priority must be -1000..1000 and expiration must be in the future")
	}
	if r.Kind == "client_ip" && net.ParseIP(r.Value) == nil {
		return errors.New("invalid IP address")
	}
	if strings.ContainsAny(r.Value, "\r\n") || strings.ContainsAny(r.Name, "\r\n") {
		return errors.New("newline not allowed")
	}
	return nil
}
func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, true)
	if !ok {
		return
	}
	var rule core.Rule
	if e := decode(r, &rule); e != nil {
		fail(w, 400, "Invalid rule JSON")
		return
	}
	if id.Role != "admin" {
		if id.Email == "" {
			fail(w, 403, "No mailbox assigned")
			return
		}
		if rule.Kind != "sender_email" && rule.Kind != "sender_domain" {
			fail(w, 403, "Mailbox rules can only match senders")
			return
		}
		rule.Owner = id.Email
		rule.Score = 0
		if rule.Action != "accept" && rule.Action != "quarantine" {
			fail(w, 400, "Mailbox rule action must be accept or quarantine")
			return
		}
	} else {
		rule.Owner = ""
	}
	if e := validRule(rule); e != nil {
		fail(w, 400, e.Error())
		return
	}
	rule.ID = core.ID()
	rule.Enabled = true
	e := s.Store.UpdateConfig(func(c *core.Config) error {
		if len(c.Rules) >= 20000 {
			return errors.New("rule limit reached")
		}
		c.Rules = append(c.Rules, rule)
		return nil
	})
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	jsonReply(w, 201, rule)
}
func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, true)
	if !ok {
		return
	}
	var rule core.Rule
	if err := decode(r, &rule); err != nil {
		fail(w, 400, "Invalid rule JSON")
		return
	}
	if id.Role != "admin" {
		if id.Email == "" {
			fail(w, 403, "Mailbox not assigned")
			return
		}
		if rule.Kind != "sender_email" && rule.Kind != "sender_domain" {
			fail(w, 403, "Mailbox rules can only match senders")
			return
		}
		if rule.Action != "accept" && rule.Action != "quarantine" {
			fail(w, 403, "Mailbox rule cannot force this action")
			return
		}
		rule.Score = 0
		rule.Priority = 0
	}
	if err := validRule(rule); err != nil {
		fail(w, 400, err.Error())
		return
	}
	var saved core.Rule
	err := s.Store.UpdateConfig(func(c *core.Config) error {
		for i, existing := range c.Rules {
			if existing.ID != r.PathValue("id") {
				continue
			}
			if id.Role != "admin" && (existing.Owner == "" || !strings.EqualFold(existing.Owner, id.Email)) {
				return errors.New("not authorized for this rule")
			}
			rule.ID = existing.ID
			rule.Owner = existing.Owner
			c.Rules[i] = rule
			saved = rule
			return nil
		}
		return errors.New("rule not found")
	})
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	jsonReply(w, 200, saved)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, true)
	if !ok {
		return
	}
	target := r.PathValue("id")
	removed := false
	e := s.Store.UpdateConfig(func(c *core.Config) error {
		for i, rule := range c.Rules {
			if rule.ID == target && (id.Role == "admin" || strings.EqualFold(rule.Owner, id.Email) && id.Email != "") {
				c.Rules = append(c.Rules[:i], c.Rules[i+1:]...)
				removed = true
				return nil
			}
		}
		return errors.New("rule not found or not permitted")
	})
	if e != nil {
		fail(w, 404, e.Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"removed": removed})
}
func (s *Server) override(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	var in struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if e := decode(r, &in); e != nil {
		fail(w, 400, "Bad request")
		return
	}
	if len(strings.TrimSpace(in.Reason)) < 5 || len(in.Reason) > 500 {
		fail(w, 400, "Reason required (5–500 chars)")
		return
	}
	if in.Action != "accept" && in.Action != "tag" && in.Action != "quarantine" && in.Action != "reject" {
		fail(w, 400, "Invalid action")
		return
	}
	m, found := s.Store.Get(r.PathValue("id"))
	if !found {
		fail(w, 404, "Message not found")
		return
	}
	if m.OriginalAction == "" {
		m.OriginalAction = m.Action
	}
	m.Action = in.Action
	m.OverrideBy = id.Name
	m.OverrideReason = in.Reason
	m.Findings = append(m.Findings, core.Finding{Symbol: "ADMIN_OVERRIDE", Source: "manual/" + id.Name, Detail: in.Reason, Score: 0})
	if e := s.Store.Save(m); e != nil {
		fail(w, 503, "Failed to persist override")
		return
	}
	jsonReply(w, 200, m)
}
func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	m, found := s.Store.Get(r.PathValue("id"))
	if !found {
		fail(w, 404, "Message not found")
		return
	}
	if m.Delivery == "released" {
		fail(w, 409, "Already released")
		return
	}
	raw, e := s.Store.Quarantined(m.ID)
	if e != nil {
		fail(w, 404, "Original message not retained; release unavailable")
		return
	}
	if s.Deliver == nil {
		fail(w, 503, "Outbound SMTP relay is not configured")
		return
	}
	if e = s.Deliver(r.Context(), m, raw); e != nil {
		s.log.Error("release failed", "message_id", m.ID, "error", e)
		fail(w, 502, "Upstream relay rejected release; message remains quarantined")
		return
	}
	m.Delivery = "released"
	m.OverrideBy = id.Name
	m.OverrideReason = "Manual quarantine release"
	m.OriginalAction = m.Action
	m.Action = "accept"
	if e = s.Store.Save(m); e != nil {
		fail(w, 503, "Delivered, but history update failed; do not retry blindly")
		return
	}
	_ = s.Store.RemoveQuarantine(m.ID)
	jsonReply(w, 200, m)
}
func (s *Server) addUser(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	var in struct{ Name, Email, Password string }
	if e := decode(r, &in); e != nil {
		fail(w, 400, "Invalid user")
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Name) < 3 || len(in.Name) > 48 || strings.ContainsAny(in.Name, " @:/\\") {
		fail(w, 400, "Invalid username")
		return
	}
	if !strings.Contains(in.Email, "@") || len(in.Email) > 254 || strings.ContainsAny(in.Email, " \r\n") {
		fail(w, 400, "Invalid mailbox")
		return
	}
	salt, hash, e := core.MakePassword(in.Password)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	u := core.User{Name: in.Name, Email: in.Email, Role: "mailbox", Salt: salt, PasswordHash: hash}
	e = s.Store.UpdateConfig(func(c *core.Config) error {
		for _, x := range c.Users {
			if strings.EqualFold(x.Name, u.Name) || strings.EqualFold(x.Email, u.Email) {
				return errors.New("username or mailbox already exists")
			}
		}
		c.Users = append(c.Users, u)
		return nil
	})
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	jsonReply(w, 201, map[string]string{"name": u.Name, "email": u.Email, "role": u.Role})
}
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	name := r.PathValue("name")
	e := s.Store.UpdateConfig(func(c *core.Config) error {
		for i, u := range c.Users {
			if u.Name == name && u.Role != "admin" {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				return nil
			}
		}
		return errors.New("user not found or cannot remove admin")
	})
	if e != nil {
		fail(w, 404, e.Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"removed": true})
}
func (s *Server) addToken(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	var in struct{ Name, Scope string }
	if e := decode(r, &in); e != nil {
		fail(w, 400, "Bad request")
		return
	}
	if len(in.Name) < 2 || len(in.Name) > 80 || (in.Scope != "scan" && in.Scope != "admin") {
		fail(w, 400, "Token requires name and scope (scan or admin)")
		return
	}
	v, hash, e := core.MakeToken()
	if e != nil {
		fail(w, 500, "Token generation failed")
		return
	}
	e = s.Store.UpdateConfig(func(c *core.Config) error {
		for _, t := range c.Tokens {
			if t.Name == in.Name {
				return errors.New("token name exists")
			}
		}
		c.Tokens = append(c.Tokens, core.Token{Name: in.Name, Hash: hash, Scope: in.Scope, Created: time.Now().UTC()})
		return nil
	})
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	jsonReply(w, 201, map[string]string{"token": v, "name": in.Name, "scope": in.Scope, "warning": "Store the token now; it cannot be retrieved later"})
}
func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	name := r.PathValue("name")
	e := s.Store.UpdateConfig(func(c *core.Config) error {
		for i, t := range c.Tokens {
			if t.Name == name {
				c.Tokens = append(c.Tokens[:i], c.Tokens[i+1:]...)
				return nil
			}
		}
		return errors.New("token not found")
	})
	if e != nil {
		fail(w, 404, e.Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"revoked": true})
}
func (s *Server) addDNSList(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	var in core.DNSList
	if e := decode(r, &in); e != nil {
		fail(w, 400, "Invalid DNS list")
		return
	}
	in.Zone = strings.ToLower(strings.TrimSpace(in.Zone))
	if len(in.Zone) < 4 || len(in.Zone) > 253 || strings.ContainsAny(in.Zone, "/ :\n\r") || in.Score < -100 || in.Score > 100 {
		fail(w, 400, "Invalid DNS zone or weight")
		return
	}
	e := s.Store.UpdateConfig(func(c *core.Config) error {
		for _, v := range c.DNSLists {
			if v.Zone == in.Zone {
				return errors.New("zone already exists")
			}
		}
		c.DNSLists = append(c.DNSLists, in)
		return nil
	})
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	jsonReply(w, 201, in)
}
func (s *Server) deleteDNSList(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	zone := r.PathValue("zone")
	e := s.Store.UpdateConfig(func(c *core.Config) error {
		for i, v := range c.DNSLists {
			if v.Zone == zone {
				c.DNSLists = append(c.DNSLists[:i], c.DNSLists[i+1:]...)
				return nil
			}
		}
		return errors.New("zone not found")
	})
	if e != nil {
		fail(w, 404, e.Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"removed": true})
}
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	// Each view has a stable URL so refresh, bookmarks and browser navigation work.
	// Only known console paths serve the UI; unknown paths remain real 404s.
	switch r.URL.Path {
	case "/", "/overview", "/messages", "/delivery-queue", "/rules", "/signals", "/learning",
		"/blocklists", "/mailboxes", "/api-keys", "/policy", "/connections", "/help",
		"/quarantine", "/investigations", "/threat-intelligence", "/scan-workbench":
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, indexHTML)
}
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	httpServer := &http.Server{Addr: addr, Handler: s.Router(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(stop)
	}()
	s.log.Info("SpamGate web listening", "address", addr)
	err := httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("web server: %w", err)
}

func (s *Server) discardQuarantine(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	m, found := s.Store.Get(r.PathValue("id"))
	if !found {
		fail(w, 404, "Message not found")
		return
	}
	if m.Delivery != "quarantined" {
		fail(w, 409, "Message is not currently held in quarantine")
		return
	}
	if e := s.Store.RemoveQuarantine(m.ID); e != nil {
		fail(w, 503, "Unable to delete original message")
		return
	}
	m.Delivery = "discarded"
	m.OverrideBy = id.Name
	m.OverrideReason = "Manual quarantine deletion"
	m.Findings = append(m.Findings, core.Finding{Symbol: "QUARANTINE_DISCARDED", Source: "manual/" + id.Name, Detail: "Raw email permanently deleted", Score: 0})
	if e := s.Store.Save(m); e != nil {
		fail(w, 503, "Message deleted, but history update failed")
		return
	}
	jsonReply(w, 200, m)
}

// signals lists the effective built-in detector weights for all authenticated users.
func (s *Server) signals(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	jsonReply(w, 200, core.ConfiguredSignals(s.Store.Config()))
}
func (s *Server) updateSignal(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	symbol := r.PathValue("symbol")
	if !core.IsBuiltinSymbol(symbol) {
		fail(w, 404, "Unknown built-in detector")
		return
	}
	var p core.SignalPolicy
	if e := decode(r, &p); e != nil || p.Score < -100 || p.Score > 100 || math.IsNaN(p.Score) || math.IsInf(p.Score, 0) {
		fail(w, 400, "Invalid signal configuration: score must be between -100 and 100")
		return
	}
	if e := s.Store.UpdateConfig(func(c *core.Config) error {
		if c.SignalPolicies == nil {
			c.SignalPolicies = make(map[string]core.SignalPolicy)
		}
		c.SignalPolicies[symbol] = p
		return nil
	}); e != nil {
		fail(w, 503, "Unable to store signal policy")
		return
	}
	for _, v := range core.ConfiguredSignals(s.Store.Config()) {
		if v.Symbol == symbol {
			jsonReply(w, 200, v)
			return
		}
	}
	fail(w, 500, "Signal configuration unavailable")
}

func (s *Server) bayesStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	jsonReply(w, 200, s.Store.BayesStats())
}
func (s *Server) bayesTrain(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	label := r.URL.Query().Get("label")
	if label != "ham" && label != "spam" {
		fail(w, 400, "Training label must be ham or spam")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, 413, "Training message exceeds 10 MiB")
		return
	}
	stats, err := s.Store.TrainBayes(raw, label)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	jsonReply(w, 200, stats)
}

// All learning mutations are administrator-only. They are deliberately
// separate from the trusted, MTA-facing HTTP scanner.
func (s *Server) fuzzyStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	jsonReply(w, 200, s.Store.FuzzyStats())
}
func (s *Server) fuzzyEntries(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	jsonReply(w, 200, s.Store.FuzzyEntries())
}
func (s *Server) fuzzyTrain(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	label := r.URL.Query().Get("label")
	if label != "spam" && label != "ham" {
		fail(w, 400, "Training label must be spam or ham")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, 413, "Training sample exceeds 10 MiB")
		return
	}
	entry, err := s.Store.TrainFuzzy(raw, label)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	jsonReply(w, 200, entry)
}
func (s *Server) fuzzyDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	err := s.Store.DeleteFuzzy(r.PathValue("id"))
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"removed": true})
}
func (s *Server) neuralStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	jsonReply(w, 200, s.Store.NeuralStats())
}
func (s *Server) neuralTrain(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	label := r.URL.Query().Get("label")
	if label != "spam" && label != "ham" {
		fail(w, 400, "Training label must be spam or ham")
		return
	}
	id := r.PathValue("id")
	if len(id) != 32 {
		fail(w, 400, "Invalid message ID")
		return
	}
	stats, err := s.Store.TrainNeural(id, label)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	jsonReply(w, 200, stats)
}
