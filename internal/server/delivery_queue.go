package server

import (
	"errors"
	"github.com/gigabytegrove/spamgate/internal/core"
	"net/http"
	"os"
)

func (s *Server) deliveryQueue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	if s.Queue == nil {
		jsonReply(w, 200, map[string]any{"enabled": false, "jobs": []any{}, "total": 0})
		return
	}
	summary, err := s.Queue.Snapshot()
	if err != nil {
		fail(w, 503, "Delivery queue unavailable")
		return
	}
	jsonReply(w, 200, summary)
}
func (s *Server) retryDelivery(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	if s.Queue == nil {
		fail(w, 409, "Durable delivery queue is disabled")
		return
	}
	if err := s.Queue.Retry(r.PathValue("id")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fail(w, 404, "Queue entry not found")
		} else {
			fail(w, 409, err.Error())
		}
		return
	}
	jsonReply(w, 200, map[string]bool{"scheduled": true})
}
func (s *Server) discardDelivery(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	if r.Header.Get("X-Confirm-Discard") != "discard queued original" {
		fail(w, 400, "Explicit discard confirmation required")
		return
	}
	if s.Queue == nil {
		fail(w, 409, "Durable delivery queue is disabled")
		return
	}
	if err := s.Queue.Discard(r.PathValue("id")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fail(w, 404, "Queue entry not found")
		} else {
			fail(w, 409, err.Error())
		}
		return
	}
	// Record destructive queue operations in the decision journal.
	if m, ok := s.Store.Get(r.PathValue("id")); ok {
		m.Delivery = "discarded"
		m.OverrideBy = identity.Name
		m.OverrideReason = "Manually discarded undelivered SMTP original"
		m.Findings = append(m.Findings, core.Finding{Symbol: "QUEUE_DISCARDED", Source: "manual/" + identity.Name, Detail: m.OverrideReason})
		if err := s.Store.Save(m); err != nil {
			s.log.Error("queue discard audit persistence failed", "id", m.ID, "error", err)
		}
	}
	s.log.Warn("queue original permanently discarded", "id", r.PathValue("id"), "actor", identity.Name)
	jsonReply(w, 200, map[string]bool{"discarded": true})
}
