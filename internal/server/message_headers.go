package server

import (
	"errors"
	"net/http"
	"os"
)

// Headers are intentionally ADMIN ONLY. They can contain private routing
// information, internal hostnames, authentication identifiers and addresses of
// recipients other than the user's mailbox. No MIME body is ever returned.
func (s *Server) messageHeaders(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	result, err := s.Store.Headers(r.PathValue("id"))
	if errors.Is(err, os.ErrNotExist) {
		fail(w, http.StatusNotFound, "Original headers were not retained for this scan. Older accepted messages cannot be reconstructed; new scans retain headers only.")
		return
	}
	if err != nil {
		s.log.Error("message header read", "error", err)
		fail(w, http.StatusInternalServerError, "Headers could not be read")
		return
	}
	jsonReply(w, http.StatusOK, result)
}
