package server

import (
	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/updater"
	"net/http"
	"os"
)

func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	result, err := updater.New().Check(r.Context(), core.Version)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if _, _, e := updater.Pending(s.Store.DataDir()); e == nil {
		result.Staged = true
	}
	result = s.annotateUpdateStatus(result)
	jsonReply(w, 200, result)
}
// annotateUpdateStatus preserves supervisor capability in check and stage responses.
func (s *Server) annotateUpdateStatus(result updater.Status) updater.Status {
	result.InstallMode = "requires_supervisor"
	if os.Getenv(updater.SupervisedEnv) == "1" { result.InstallMode = "supervised"
		result.InstallPath = updater.ActiveBinaryPath(s.Store.DataDir())
	}
	if record,e:=updater.LastRecord(s.Store.DataDir());e==nil { result.LastUpdate=record }
	return result
}
func (s *Server) stageUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	result, err := updater.New().Stage(r.Context(), core.Version, s.Store.DataDir())
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	jsonReply(w, 200, s.annotateUpdateStatus(result))
}

func (s *Server) installUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	if s.UpdateExit == nil {
		fail(w, 409, "Update restart unavailable in this runtime")
		return
	}
	if r.Header.Get("X-Confirm-Update") != "install verified update" {
		fail(w, 400, "Explicit update confirmation required")
		return
	}
	if _, err := updater.ReadyForSupervisorUpdate(s.Store.DataDir()); err != nil {
		fail(w, 409, err.Error())
		return
	}
	jsonReply(w, 202, map[string]any{"restarting": true, "message": "SpamGate is installing the verified update and restarting"})
	s.UpdateExit()
}
