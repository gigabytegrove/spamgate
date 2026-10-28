package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Session identifiers and CSRF tokens are stored only in the protected data
// directory. The file never contains passwords. Expiry is absolute and cannot
// be extended by restarting or upgrading the application.
func (s *Server) loadSessions() error {
	data, err := os.ReadFile(s.sessionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var sessions map[string]session
	if err := json.Unmarshal(data, &sessions); err != nil {
		return err
	}
	now := time.Now()
	for token, item := range sessions {
		if token == "" || !item.Identity.Session || item.Identity.CSRF == "" || !item.Expires.After(now) {
			continue
		}
		s.sessions[token] = item
	}
	return nil
}

// Call with s.mu held. Atomic replacement prevents half-written session files.
func (s *Server) persistSessionsLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.sessionPath), 0700); err != nil {
		return err
	}
	active := make(map[string]session)
	now := time.Now()
	for token, ss := range s.sessions {
		if token != "" && ss.Expires.After(now) && ss.Identity.Session && ss.Identity.CSRF != "" {
			active[token] = ss
		}
	}
	data, err := json.Marshal(active)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.sessionPath), ".sessions-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.sessionPath)
}
