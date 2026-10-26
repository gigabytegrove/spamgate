package server

import (
	"github.com/gigabytegrove/spamgate/internal/core"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func (s *Server) searchHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, false, false)
	if !ok {
		return
	}
	mailbox := ""
	if id.Role != "admin" {
		mailbox = id.Email
		if mailbox == "" {
			fail(w, 403, "Mailbox not assigned")
			return
		}
	}
	params := r.URL.Query()
	limit := 50
	offset := 0
	if params.Has("limit") {
		v, e := strconv.Atoi(params.Get("limit"))
		if e != nil {
			fail(w, 400, "Invalid limit")
			return
		}
		limit = v
	}
	if params.Has("offset") {
		v, e := strconv.Atoi(params.Get("offset"))
		if e != nil {
			fail(w, 400, "Invalid offset")
			return
		}
		offset = v
	}
	q := core.HistoryQuery{Text: params.Get("q"), Action: params.Get("action"), Sender: params.Get("sender"), Recipient: params.Get("recipient"), Limit: limit, Offset: offset}
	if params.Has("from") {
		v, e := time.Parse(time.RFC3339, params.Get("from"))
		if e != nil {
			fail(w, 400, "from must be RFC3339")
			return
		}
		q.From = v
	}
	if params.Has("to") {
		v, e := time.Parse(time.RFC3339, params.Get("to"))
		if e != nil {
			fail(w, 400, "to must be RFC3339")
			return
		}
		q.To = v
	}
	if len(q.Text) > 256 || len(q.Sender) > 256 || len(q.Recipient) > 256 {
		fail(w, 400, "Search input too long")
		return
	}
	result, e := s.Store.SearchHistory(q, mailbox)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	jsonReply(w, 200, result)
}

// A quarantine preview is *never* rendered as HTML and intentionally omits
// links, embedded remote images, and attachments. It is admin-only.
func (s *Server) quarantinePreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	raw, e := s.Store.Quarantined(r.PathValue("id"))
	if e != nil {
		fail(w, 404, "No retained quarantine original")
		return
	}
	// Limit to an escaped, short, printable representation; never send MIME bytes
	// as text/html. This is a raw text preview, not a MIME-decoded message body.
	text := strings.Builder{}
	for _, char := range string(raw) {
		if text.Len() >= 4096 {
			break
		}
		if char == '\n' || char == '\r' || char == '\t' || (unicode.IsPrint(char) && char != '\u202e' && char != '\u202d') {
			text.WriteRune(char)
		}
	}
	jsonReply(w, 200, map[string]any{"preview": text.String(), "truncated": len(raw) > 4096, "format": "text/plain", "warning": "Raw, truncated email. Do not trust links or content."})
}
func (s *Server) simulateScan(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		fail(w, 413, "Scan input exceeds 10 MiB")
		return
	}
	client := r.Header.Get("X-SpamGate-Client-IP")
	if client != "" && net.ParseIP(client) == nil {
		fail(w, 400, "Invalid client IP")
		return
	}
	recipients := []string{}
	for _, rcpt := range strings.Split(r.Header.Get("X-SpamGate-Recipients"), ",") {
		if rcpt = strings.TrimSpace(rcpt); rcpt != "" {
			recipients = append(recipients, rcpt)
		}
	}
	result, e := s.Scanner.Scan(r.Context(), core.Input{Raw: raw, Sender: r.Header.Get("X-SpamGate-Sender"), Recipients: recipients, ClientIP: client, Connector: "simulation"})
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	jsonReply(w, 200, map[string]any{"simulation": true, "persisted": false, "message": result})
}
