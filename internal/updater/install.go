package updater

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type installPlan struct {
	Target     string   `json:"target"`
	DataDir    string   `json:"data_dir"`
	Arguments  []string `json:"arguments"`
	WorkingDir string   `json:"working_dir"`
	Parent     int      `json:"parent"`
}

// Launch starts an independent, copied helper so Windows can replace the running executable.
// It does not modify the current executable before the caller initiates shutdown.
func Launch(dataDir string) error {
	if os.Getenv("INVOCATION_ID") != "" || os.Getenv("NOTIFY_SOCKET") != "" || os.Getenv("SPAMGATE_MANAGED_SERVICE") == "true" {
		return errors.New("service-managed installations must be upgraded by the service manager")
	}
	if _, _, err := Pending(dataDir); err != nil {
		return fmt.Errorf("no verified staged update: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir, "updates")
	original, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer original.Close()
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	suffix := hex.EncodeToString(nonce)
	helper := filepath.Join(dir, ".update-helper-"+suffix+filepath.Ext(exe))
	out, err := os.OpenFile(helper, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, original); err != nil {
		out.Close()
		os.Remove(helper)
		return err
	}
	if err = out.Sync(); err != nil {
		out.Close()
		os.Remove(helper)
		return err
	}
	if err = out.Close(); err != nil {
		os.Remove(helper)
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		os.Remove(helper)
		return err
	}
	plan := installPlan{Target: exe, DataDir: dataDir, Arguments: os.Args[1:], WorkingDir: cwd, Parent: os.Getpid()}
	manifest := filepath.Join(dir, ".update-plan-"+suffix+".json")
	b, err := json.Marshal(plan)
	if err != nil {
		os.Remove(helper)
		return err
	}
	if err = os.WriteFile(manifest, b, 0600); err != nil {
		os.Remove(helper)
		return err
	}
	cmd := exec.Command(helper, "-internal-update-apply", manifest)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err = cmd.Start(); err != nil {
		os.Remove(helper)
		os.Remove(manifest)
		return err
	}
	return cmd.Process.Release()
}

// ApplyFromHelper runs only in the short-lived copy launched by Launch. The
// update is reversible: a failed replacement or startup attempt restores .bak.
func ApplyFromHelper(manifest string) error {
	if !filepath.IsAbs(manifest) {
		return errors.New("absolute update plan path required")
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	var p installPlan
	if err = json.Unmarshal(raw, &p); err != nil {
		return err
	}
	if !filepath.IsAbs(p.Target) || !filepath.IsAbs(p.DataDir) || p.Parent < 1 {
		return errors.New("invalid update plan")
	}
	if !strings.HasPrefix(filepath.Clean(manifest), filepath.Join(p.DataDir, "updates")+string(filepath.Separator)) {
		return errors.New("plan located outside update directory")
	}
	staged, _, err := Pending(p.DataDir)
	if err != nil {
		return err
	}
	// Allow the HTTP response and the original SpamGate process to shut down.
	time.Sleep(2 * time.Second)
	backup := p.Target + ".spamgate-backup"
	if _, err = os.Stat(backup); err == nil {
		return errors.New("previous executable backup exists; refusing to overwrite")
	}
	for i := 0; i < 45; i++ {
		err = os.Rename(p.Target, backup)
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("cannot replace running executable: %w", err)
	}
	if err = os.Rename(staged, p.Target); err != nil {
		_ = os.Rename(backup, p.Target)
		return fmt.Errorf("cannot install staged update: %w", err)
	}
	if err = os.Chmod(p.Target, 0700); err != nil {
		_ = os.Remove(p.Target)
		_ = os.Rename(backup, p.Target)
		return err
	}
	cmd := exec.Command(p.Target, p.Arguments...)
	cmd.Dir = p.WorkingDir
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		_ = os.Remove(p.Target)
		_ = os.Rename(backup, p.Target)
		return fmt.Errorf("new executable could not start; previous version restored: %w", err)
	}
	_ = cmd.Process.Release()
	_ = os.Remove(manifest)
	_ = os.Remove(filepath.Join(p.DataDir, "updates", "pending.json"))
	return nil
}
