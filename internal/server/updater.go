package server

import (
	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/updater"
	"net/http"
	"os"
 "strings"
)

// The original permanent launcher cannot parse a +BUILD update manifest.
// Do not trigger a restart that its older update code would inevitably reject.
func needsBuildAwareLauncher(release string) bool {
 return strings.Contains(release,"+") && os.Getenv("SPAMGATE_SPLIT_WORKER")=="1" &&
  os.Getenv("SPAMGATE_SUPPORTS_BUILD_IDS")!="1"
}

// localUpdateStatus reports installed-worker and supervisor readiness without
// contacting GitHub. Opening the Updates page must never imply an absent
// supervisor merely because no release check has been requested.
func (s *Server) localUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	status := updater.Status{Current: core.Version, CurrentBuild: core.BuildVersion}
	if _, version, err := updater.Pending(s.Store.DataDir()); err == nil {
  status.Staged=true
  status.RequiresLauncherUpgrade=needsBuildAwareLauncher(version)
 }
	jsonReply(w, http.StatusOK, s.annotateUpdateStatus(status))
}

func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	result, err := updater.New().Check(r.Context(), core.Version)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if _, version, e := updater.Pending(s.Store.DataDir()); e == nil {
  result.Staged=true
  result.RequiresLauncherUpgrade=needsBuildAwareLauncher(version)
 }
	result = s.annotateUpdateStatus(result)
	jsonReply(w, 200, result)
}
// annotateUpdateStatus preserves supervisor capability in check and stage responses.
func (s *Server) annotateUpdateStatus(result updater.Status) updater.Status {
	if result.CurrentBuild=="" {result.CurrentBuild=core.BuildVersion}
 if needsBuildAwareLauncher(result.Latest) {
  result.RequiresLauncherUpgrade=true
 }
 if result.RequiresLauncherUpgrade {
  result.Message="Installed permanent launcher predates numbered releases. A separately approved launcher migration is required before a build-numbered in-app update; no service will be restarted."
 }
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
	client:=updater.New()
 check,err:=client.Check(r.Context(),core.Version)
 if err!=nil {fail(w,502,err.Error());return}
 if needsBuildAwareLauncher(check.Latest) {
  fail(w,409,"The installed permanent launcher does not support numbered release manifests. No update was staged or restarted.")
  return
 }
 result, err := client.Stage(r.Context(), core.Version, s.Store.DataDir())
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
	if _, stagedVersion, err := updater.Pending(s.Store.DataDir()); err==nil && needsBuildAwareLauncher(stagedVersion) {
  fail(w,409,"The current launcher cannot install a numbered build. No restart was requested.")
  return
 }
 if _, err := updater.ReadyForSupervisorUpdate(s.Store.DataDir()); err != nil {
		fail(w, 409, err.Error())
		return
	}
	jsonReply(w, 202, map[string]any{"restarting": true, "message": "SpamGate is installing the verified update and restarting"})
	s.UpdateExit()
}
