package updater

// The integrated supervisor is a second invocation of the same SpamGate binary,
// not a privileged daemon, Docker socket client, or updater sidecar. The parent
// keeps ownership of the service lifecycle while child binaries are replaced.
// Updates live in the persistent data volume; the root-owned base executable is
// never overwritten by an unprivileged service.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const UpdateRestartExitCode = 75
const SupervisedEnv = "SPAMGATE_SUPERVISED"

// UpdateRecord records an observable result. The API must not report an
// upgrade as successful merely because an HTTP request terminated the child.
type UpdateRecord struct {
	State   string    `json:"state"`
	Version string    `json:"version,omitempty"`
	Detail  string    `json:"detail"`
	At      time.Time `json:"at"`
}

func updateDir(dir string) string { return filepath.Join(dir, "updates") }
func runningPath(dir string) string {
	return filepath.Join(updateDir(dir), "running"+filepath.Ext(mustExecutableName()))
}
func mustExecutableName() string {
	if v, err := platformAsset(); err == nil {
		return v
	}
	return "spamgate"
}
func lastRecordPath(dir string) string { return filepath.Join(updateDir(dir), "last-update.json") }

func Record(dir, state, version, detail string) error {
	if err := os.MkdirAll(updateDir(dir), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(UpdateRecord{State: state, Version: version, Detail: detail, At: time.Now().UTC()})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(updateDir(dir), ".update-record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), lastRecordPath(dir))
}
func LastRecord(dir string) (*UpdateRecord, error) {
	raw, err := os.ReadFile(lastRecordPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result UpdateRecord
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ReadyForSupervisorUpdate performs the checks *before* the caller requests a
// shutdown. Unsupervised containers and service units must never be killed by
// the in-app updater, because no independent process can restore them.
func ReadyForSupervisorUpdate(dataDir string) (string, error) {
	if os.Getenv(SupervisedEnv) != "1" {
		return "", errors.New("in-app restart requires the integrated SpamGate supervisor; install the new native service unit or Docker image once to enable future zero-manual-copy updates")
	}
	staged, version, err := Pending(dataDir)
	if err != nil {
		return "", fmt.Errorf("staged update verification failed: %w", err)
	}
	_ = staged
	return version, nil
}

func copyExecutable(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("update must be a regular file")
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".spamgate-exe-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0700); err != nil {
		temp.Close()
		return err
	}
	if _, err = io.Copy(temp, input); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), target)
}

func promoteStaged(dir, base string) (string, error) {
	staged, version, err := Pending(dir)
	if err != nil {
		return "", err
	}
	current := runningPath(dir)
	previous := filepath.Join(updateDir(dir), "running.previous"+filepath.Ext(mustExecutableName()))
	active := current
	if _, err := os.Stat(active); errors.Is(err, os.ErrNotExist) {
		active = base
	}
	// Keep a known runnable executable for rollback before replacing anything.
	if err := copyExecutable(active, previous); err != nil {
		return "", fmt.Errorf("preserve previous executable: %w", err)
	}
	if err := copyExecutable(staged, current); err != nil {
		return "", fmt.Errorf("stage active executable: %w", err)
	}
	return version, nil
}
func verifyExecutableVersion(binary, expected string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-version").Output()
	if err != nil {
		return fmt.Errorf("replacement version check failed: %w", err)
	}
	if got := strings.TrimSpace(string(output)); got != strings.TrimPrefix(expected, "v") {
		return fmt.Errorf("replacement identifies as %q, expected %q", got, strings.TrimPrefix(expected, "v"))
	}
	return nil
}
func rollback(dir string) error {
	previous := filepath.Join(updateDir(dir), "running.previous"+filepath.Ext(mustExecutableName()))
	return copyExecutable(previous, runningPath(dir))
}
func clearPending(dir string) {
	_ = os.Remove(filepath.Join(updateDir(dir), "pending.json"))
	_ = os.Remove(filepath.Join(updateDir(dir), "pending"+filepath.Ext(mustExecutableName())))
}

// superviseChild runs a child with a preserved inherited environment and working
// directory. There is exactly one SpamGate HTTP/Milter worker at a time.
func superviseChild(ctx context.Context, binary string, args []string) (*exec.Cmd, <-chan error, error) {
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), SupervisedEnv+"=1", "SPAMGATE_OPEN_BROWSER=false")
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return cmd, done, nil
}
func readyURL(args []string) string {
	listen := os.Getenv("SPAMGATE_WEB_LISTEN")
	if listen == "" {
		listen = "0.0.0.0:38470"
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "-listen" && i+1 < len(args) {
			listen = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "-listen=") {
			listen = strings.TrimPrefix(args[i], "-listen=")
		}
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}
func waitHealthy(ctx context.Context, url string, done <-chan error, timeout time.Duration) error {
	if url == "" {
		return errors.New("cannot derive local management health URL")
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: 400 * time.Millisecond}
	for {
		select {
		case err := <-done:
			return fmt.Errorf("replacement exited before becoming healthy: %v", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return errors.New("replacement did not pass local health check before timeout")
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err == nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}
}

// Supervise is invoked by systemd or Docker as the permanent parent. It can
// recover from failed upgrades without terminating the service/container.
// A failed ordinary worker is returned to the OS supervisor, never concealed.
func Supervise(ctx context.Context, args []string, dir string) error {
	base, err := os.Executable()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(updateDir(dir), 0700); err != nil {
		return err
	}
	active := base
	if info, e := os.Stat(runningPath(dir)); e == nil && info.Mode().IsRegular() {
		// A newer immutable base image or native install takes precedence over
		// an older persistent overlay; never silently downgrade on restart.
		baseOutput, baseErr := exec.Command(base, "-version").Output()
		overlayOutput, overlayErr := exec.Command(runningPath(dir), "-version").Output()
		if baseErr == nil && overlayErr == nil {
			cmp, err := compare(strings.TrimSpace(string(overlayOutput)), strings.TrimSpace(string(baseOutput)))
			if err == nil && cmp >= 0 {
				active = runningPath(dir)
			}
		} else {
			active = runningPath(dir)
		}
	}
	url := readyURL(args)
	for {
		child, done, err := superviseChild(ctx, active, args)
		if err != nil { // A broken overlay must never prevent a known working base from starting.
			if active != base {
				_ = Record(dir, "failed", "", "Saved executable could not launch; restoring base: "+err.Error())
				active = base
				continue
			}
			return err
		}
		select {
		case <-ctx.Done():
			_ = child.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(7 * time.Second):
				_ = child.Process.Kill()
				<-done
			}
			return nil
		case err = <-done:
			var exit *exec.ExitError
			if err == nil {
				return nil
			}
			if !errors.As(err, &exit) || exit.ExitCode() != UpdateRestartExitCode {
				return fmt.Errorf("SpamGate worker exited unexpectedly: %w", err)
			}
		}
		// Only a verified, explicitly requested update can trigger a new worker.
		version, err := promoteStaged(dir, base)
		if err != nil {
			_ = Record(dir, "failed", "", "Update did not install; restarting previous worker: "+err.Error())
			continue
		}
		if err = verifyExecutableVersion(runningPath(dir), version); err != nil {
			if e := rollback(dir); e != nil {
				return fmt.Errorf("version mismatch and rollback failed: %w; %v", err, e)
			}
			_ = Record(dir, "rolled_back", version, "Replacement rejected before startup: "+err.Error())
			clearPending(dir)
			active = runningPath(dir)
			continue
		}
		if err = Record(dir, "checking", version, "Installed; checking the replacement process before reporting success"); err != nil {
			return err
		}
		active = runningPath(dir)
		replacement, healthDone, startErr := superviseChild(ctx, active, args)
		if startErr == nil {
			healthCtx, cancel := context.WithCancel(ctx)
			startErr = waitHealthy(healthCtx, url, healthDone, 18*time.Second)
			cancel()
		}
		if startErr != nil {
			if replacement != nil {
				_ = replacement.Process.Kill()
				select {
				case <-healthDone:
				case <-time.After(2 * time.Second):
				}
			}
			if e := rollback(dir); e != nil {
				_ = Record(dir, "failed", version, "Replacement unhealthy and rollback failed: "+e.Error())
				return fmt.Errorf("update failed: %w; rollback failed: %v", startErr, e)
			}
			_ = Record(dir, "rolled_back", version, "Replacement did not become healthy; prior executable restored: "+startErr.Error())
			active = runningPath(dir)
			clearPending(dir)
			continue
		}
		clearPending(dir)
		_ = Record(dir, "healthy", version, "Replacement passed local /healthz. SMTP delivery still requires independent verification")
		// Keep monitoring the running replacement; avoid spawning another copy.
		select {
		case <-ctx.Done():
			_ = replacement.Process.Signal(os.Interrupt)
			select {
			case <-healthDone:
			case <-time.After(7 * time.Second):
				_ = replacement.Process.Kill()
				<-healthDone
			}
			return nil
		case err = <-healthDone:
			var exit *exec.ExitError
			if err == nil {
				return nil
			}
			if errors.As(err, &exit) && exit.ExitCode() == UpdateRestartExitCode {
				continue
			}
			return fmt.Errorf("updated SpamGate worker exited unexpectedly: %w", err)
		}
	}
}
