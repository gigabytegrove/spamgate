package server

import (
	"github.com/gigabytegrove/spamgate/internal/core"
	"net/http"
)

// An administrator replaces the complete small policy set in one atomic write.
// This avoids partial updates that would produce inconsistent mail decisions.
func (s *Server) updateRecipientPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	var in struct {
		Policies []core.RecipientPolicy `json:"policies"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "Expected policies array with mailbox and ordered thresholds")
		return
	}
	err := s.Store.UpdateConfig(func(c *core.Config) error {
		c.RecipientPolicies = in.Policies
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	jsonReply(w, 200, map[string]any{"policies": s.Store.Config().RecipientPolicies})
}
