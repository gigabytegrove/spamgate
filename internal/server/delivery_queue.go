package server

import (
	"errors"
	"net/http"
	"os"
)

func (s *Server) deliveryQueue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	w.Header().Set("Cache-Control", "no-store")
	identity, ok := s.authorized(w, r, true, true)
 if !ok {
		return
	}
	if s.Queue == nil {
		fail(w, 409, "Durable delivery queue is disabled")
		return
	}
	if err := s.Queue.RetryWithAudit(r.PathValue("id"), identity.Name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fail(w, 404, "Queue entry not found")
		} else {
			s.log.Error("delivery retry failed or requires audit reconciliation", "id", r.PathValue("id"), "actor", identity.Name, "error", err)
			fail(w, 409, deliveryQueueMutationFailure("retry"))
		}
		return
	}
	jsonReply(w, 200, map[string]bool{"scheduled": true})
}
func (s *Server) discardDelivery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	if err := s.Queue.DiscardWithAudit(r.PathValue("id"), identity.Name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fail(w, 404, "Queue entry not found")
		} else {
			s.log.Error("queue discard failed or requires audit reconciliation", "id", r.PathValue("id"), "actor", identity.Name, "error", err)
			fail(w, 409, deliveryQueueMutationFailure("discard"))
		}
		return
	}
	s.log.Warn("queue original permanently discarded", "id", r.PathValue("id"), "actor", identity.Name)
	jsonReply(w, 200, map[string]bool{"discarded": true})
}

// deliveryQueueMutationFailure deliberately excludes backend errors. Durable
// queue errors may contain private spool paths, message identifiers, or host
// configuration. Operators receive full diagnostics in the server log only.
func deliveryQueueMutationFailure(action string) string {
	switch action {
	case "retry":
		return "Delivery retry could not be scheduled; inspect server logs and queue state before retrying"
	case "discard":
		return "Delivery discard was not confirmed; inspect server logs and queue state before retrying"
	default:
		return "Delivery queue operation could not be completed; inspect server logs"
	}
}
