package main

// spamgate (native launcher) is an independently compiled, deliberately non-updating process
// supervisor for native SpamGate installations. It never loads mail config or
// holds HTTP/Milter sockets. All mail traffic and UI run in the spamgate worker.
// Unlike the legacy detached updater, failures cannot silently kill the parent.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

const restartExitCode = 75
const maxDownload = 80 << 20

var versionPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$`)
var digestPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type options struct {
	worker string
	data   string
	listen string
	args   []string
}

type updateRecord struct {
	State   string    `json:"state"`
	Version string    `json:"version,omitempty"`
	Detail  string    `json:"detail"`
	At      time.Time `json:"at"`
}

type updateManifest struct {
	Version  string
	Filename string
	SHA256   string
}

func main() {
	if err := run(); err != nil {
		log.Printf("SpamGate launcher: %v", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(core.Version)
		return nil
	}
	if os.Getenv("SPAMGATE_SUPERVISED") == "1" {
		return errors.New("nested SpamGate launcher refused")
	}
	opts, err := parse(os.Args[1:])
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return supervise(ctx, opts)
}

func parse(args []string) (options, error) {
	self, err := os.Executable()
	if err != nil {
		return options{}, err
	}
	worker := filepath.Join(filepath.Dir(self), "spamgate-worker")
	// The runner only interprets these control flags. All other arguments are
	// forwarded unchanged to the worker, including -data and -listen.
	opts := options{worker: worker, data: "/var/lib/spamgate", listen: os.Getenv("SPAMGATE_WEB_LISTEN"), args: []string{}}
	if opts.listen == "" {
		opts.listen = "0.0.0.0:38470"
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-worker" {
			if i+1 >= len(args) {
				return opts, errors.New("-worker requires an absolute path")
			}
			i++
			opts.worker = args[i]
			continue
		}
		if strings.HasPrefix(arg, "-worker=") {
			opts.worker = strings.TrimPrefix(arg, "-worker=")
			continue
		}
		if arg == "-data" {
			if i+1 >= len(args) {
				return opts, errors.New("-data requires a directory")
			}
			opts.data = args[i+1]
		} else if strings.HasPrefix(arg, "-data=") {
			opts.data = strings.TrimPrefix(arg, "-data=")
		} else if arg == "-listen" {
			if i+1 >= len(args) {
				return opts, errors.New("-listen requires an address")
			}
			opts.listen = args[i+1]
		} else if strings.HasPrefix(arg, "-listen=") {
			opts.listen = strings.TrimPrefix(arg, "-listen=")
		}
		opts.args = append(opts.args, arg)
		if (arg == "-data" || arg == "-listen") && i+1 < len(args) {
			i++
			opts.args = append(opts.args, args[i])
		}
	}
	if !filepath.IsAbs(opts.worker) || !filepath.IsAbs(opts.data) {
		return opts, errors.New("worker and data paths must be absolute")
	}
	if opts.worker == "/" || opts.data == "/" {
		return opts, errors.New("unsafe filesystem path")
	}
	if _, err := os.Stat(opts.worker); err != nil {
		return opts, fmt.Errorf("worker missing at %s: %w", opts.worker, err)
	}
	return opts, nil
}

func updateFolder(o options) string { return filepath.Join(o.data, "updates") }
func record(o options, state, version, detail string) {
	folder := updateFolder(o)
	if err := os.MkdirAll(folder, 0700); err != nil {
		log.Printf("update journal unavailable: %v", err)
		return
	}
	raw, _ := json.Marshal(updateRecord{State: state, Version: version, Detail: detail, At: time.Now().UTC()})
	tmp, err := os.CreateTemp(folder, ".runner-state-*")
	if err != nil {
		log.Printf("update journal unavailable: %v", err)
		return
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if e := tmp.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(folder, "last-update.json"))
	}
	if err != nil {
		log.Printf("update journal unavailable: %v", err)
	}
}
func regularFile(path string) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular executable: %s", path)
	}
	return nil
}
func copyAtomic(source, target string) error {
	if err := regularFile(source); err != nil {
		return err
	}
	if info, err := os.Lstat(target); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("target is not a regular file: %s", target)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()
	f, err := os.CreateTemp(filepath.Dir(target), ".spamgate-replacement-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0700); err == nil {
		_, err = io.Copy(f, src)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), target)
}
func staged(o options) (string, string, error) {
	folder := updateFolder(o)
	b, err := os.ReadFile(filepath.Join(folder, "pending.json"))
	if err != nil {
		return "", "", err
	}
	var m updateManifest
	if err = json.Unmarshal(b, &m); err != nil {
		return "", "", err
	}
	expected := "spamgate-worker-linux-amd64"
	if runtime.GOOS == "windows" {
		expected = "spamgate-windows-amd64.exe"
	}
	if runtime.GOARCH != "amd64" || !versionPattern.MatchString(m.Version) || m.Filename != expected || !digestPattern.MatchString(m.SHA256) {
		return "", "", errors.New("invalid staged manifest")
	}
	filename := "pending" + filepath.Ext(expected)
	path := filepath.Join(folder, filename)
	if err = regularFile(path); err != nil {
		return "", "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", "", err
	}
	if info.Size() < 4096 || info.Size() > maxDownload {
		return "", "", errors.New("staged binary size invalid")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", "", err
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(m.SHA256) {
		return "", "", errors.New("staged binary hash mismatch")
	}
	return path, strings.TrimPrefix(m.Version, "v"), nil
}
func compareVersions(a, b string) (int, error) {
	decode := func(raw string) ([]int, error) {
		raw = strings.TrimPrefix(raw, "v")
		parts := strings.SplitN(raw, "-", 2)
		fields := strings.Split(parts[0], ".")
		if len(fields) != 3 {
			return nil, errors.New("invalid version")
		}
		out := make([]int, 5)
		for i, x := range fields {
			n, e := strconv.Atoi(x)
			if e != nil {
				return nil, e
			}
			out[i] = n
		}
		out[3] = 4 // stable > RC > beta > alpha
		if len(parts) == 2 {
			pre := strings.Split(parts[1], ".")
			if len(pre) != 2 {
				return nil, errors.New("invalid prerelease")
			}
			rank := map[string]int{"alpha": 1, "beta": 2, "rc": 3}
			out[3] = rank[pre[0]]
			if out[3] == 0 {
				return nil, errors.New("invalid prerelease")
			}
			n, e := strconv.Atoi(pre[1])
			if e != nil {
				return nil, e
			}
			out[4] = n
		}
		return out, nil
	}
	x, err := decode(a)
	if err != nil {
		return 0, err
	}
	y, err := decode(b)
	if err != nil {
		return 0, err
	}
	for i := range x {
		if x[i] > y[i] {
			return 1, nil
		}
		if x[i] < y[i] {
			return -1, nil
		}
	}
	return 0, nil
}

func clearStaged(o options) {
	folder := updateFolder(o)
	_ = os.Remove(filepath.Join(folder, "pending.json"))
	_ = os.Remove(filepath.Join(folder, "pending"+filepath.Ext(o.worker)))
}
func executableVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, path, "-version").Output()
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(b))
	if !versionPattern.MatchString(version) {
		return "", fmt.Errorf("invalid version output %q", version)
	}
	return strings.TrimPrefix(version, "v"), nil
}
func healthURL(o options) (string, error) {
	host, port, err := net.SplitHostPort(o.listen)
	if err != nil {
		return "", err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
func waitHealthy(ctx context.Context, url, version string, exited <-chan error) error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	limit := time.NewTimer(18 * time.Second)
	defer limit.Stop()
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("worker exited before becoming healthy: %v", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-limit.C:
			return errors.New("worker did not become healthy within 18 seconds")
		case <-ticker.C:
			r, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if e != nil {
				return e
			}
			resp, e := client.Do(r)
			if e != nil {
				continue
			}
			raw, e := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			if e != nil || resp.StatusCode != 200 {
				continue
			}
			var body struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(raw, &body) == nil && body.Version == version {
				return nil
			}
		}
	}
}
func launch(o options) (*exec.Cmd, <-chan error, error) {
	cmd := exec.Command(o.worker, o.args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(), "SPAMGATE_SUPERVISED=1", "SPAMGATE_INSTALLED_WORKER="+o.worker, "SPAMGATE_SPLIT_WORKER=1", "SPAMGATE_OPEN_BROWSER=false")
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	completed := make(chan error, 1)
	go func() { completed <- cmd.Wait(); close(completed) }()
	return cmd, completed, nil
}
func shutdown(cmd *exec.Cmd, completed <-chan error) {
	if cmd == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-completed:
	case <-time.After(7 * time.Second):
		_ = cmd.Process.Kill()
		<-completed
	}
}
func isUpdateExit(err error) bool {
	var ex *exec.ExitError
	return errors.As(err, &ex) && ex.ExitCode() == restartExitCode
}
func startHealthy(ctx context.Context, o options, url, expected string) (*exec.Cmd, <-chan error, error) {
	cmd, done, err := launch(o)
	if err != nil {
		return nil, nil, err
	}
	if err = waitHealthy(ctx, url, expected, done); err != nil {
		shutdown(cmd, done)
		return nil, nil, err
	}
	return cmd, done, nil
}

const workerProbeInterval = 15 * time.Second
const workerProbeFailureLimit = 3

// A healthy HTTP endpoint does not certify Milter delivery, but persistent
// health failures must not leave a hung worker holding both service ports.
func probeWorkerHealth(ctx context.Context, url, expected string) error {
	requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health HTTP status %d", resp.StatusCode)
	}
	var body struct { Version string `json:"version"` }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2048)).Decode(&body); err != nil {
		return fmt.Errorf("invalid health response: %w", err)
	}
	if body.Version != expected {
		return fmt.Errorf("worker health version mismatch: expected %s, received %s", expected, body.Version)
	}
	return nil
}

func restartBackoff(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	delay := 2 * time.Second
	for i := 1; i < failures && delay < 30*time.Second; i++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func waitRestart(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Unlike a fixed three-crash cutoff, recovery remains active while the
// foreground launcher lives. Every failed start is logged and rate-limited.
func recoverWorker(ctx context.Context, o options, url, expected string, failures int) (*exec.Cmd, <-chan error, error) {
	for {
		if err := waitRestart(ctx, restartBackoff(failures)); err != nil {
			return nil, nil, err
		}
		child, done, err := startHealthy(ctx, o, url, expected)
		if err == nil {
			return child, done, nil
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		failures++
		log.Printf("SpamGate launcher: worker start/health failed (attempt %d): %v; will retry", failures, err)
	}
}

func supervise(ctx context.Context, o options) error {
	if runtime.GOOS != "linux" {
		return errors.New("SpamGate split launcher currently supports native Linux; Windows update requires a Windows-specific replacement procedure")
	}
	if err := regularFile(o.worker); err != nil {
		return err
	}
	if err := os.MkdirAll(updateFolder(o), 0700); err != nil {
		return err
	}
	// Prevent multiple independent launchers from owning the same installed
	// executable or processing the same pending update concurrently.
	lock, err := os.OpenFile(filepath.Join(updateFolder(o), "runner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another SpamGate runner already holds this data directory: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	url, err := healthURL(o)
	if err != nil {
		return err
	}
	version, err := executableVersion(o.worker)
	if err != nil {
		return fmt.Errorf("installed worker version: %w", err)
	}
	child, done, err := recoverWorker(ctx, o, url, version, 0)
	if err != nil {
		if ctx.Err() != nil { return nil }
		return fmt.Errorf("worker startup: %w", err)
	}
	log.Printf("SpamGate launcher: worker PID %d version %s, installed at %s", child.Process.Pid, version, o.worker)
	failures := 0
	healthySince := time.Now()
	probeFailures := 0
	probeTicker := time.NewTicker(workerProbeInterval)
	defer probeTicker.Stop()
	previous := filepath.Join(updateFolder(o), "managed.previous"+filepath.Ext(o.worker))
	for {
		select {
		case <-ctx.Done():
			shutdown(child, done)
			return nil
		case <-probeTicker.C:
			if probeErr := probeWorkerHealth(ctx, url, version); probeErr != nil {
				probeFailures++
				log.Printf("SpamGate launcher: worker health failure %d/%d: %v", probeFailures, workerProbeFailureLimit, probeErr)
				if probeFailures < workerProbeFailureLimit { continue }
				shutdown(child, done)
				err = fmt.Errorf("worker unhealthy for %d probes: %w", probeFailures, probeErr)
			} else {
				probeFailures = 0
				continue
			}
		case err = <-done:
		}
		if !isUpdateExit(err) {
			if err == nil { return nil }
			if time.Since(healthySince) >= 5*time.Minute { failures = 0 }
			failures++
			log.Printf("SpamGate launcher: worker failure %d: %v; recovering with bounded backoff", failures, err)
			child, done, err = recoverWorker(ctx, o, url, version, failures)
			if err != nil {
				if ctx.Err() != nil { return nil }
				return fmt.Errorf("worker recovery: %w", err)
			}
			healthySince = time.Now()
			probeFailures = 0
			log.Printf("SpamGate launcher: worker recovered, PID %d", child.Process.Pid)
			continue
		}
		failures = 0
		probeFailures = 0
		pending, newVersion, err := staged(o)
		if err == nil {
			var cmp int
			cmp, err = compareVersions(newVersion, version)
			if err == nil && cmp <= 0 {
				err = fmt.Errorf("refusing non-forward update %s from %s", newVersion, version)
			}
		}
		if err == nil {
			err = copyAtomic(o.worker, previous)
		}
		if err == nil {
			err = copyAtomic(pending, o.worker)
		}
		if err != nil {
			record(o, "failed", newVersion, "update refused: "+err.Error())
			log.Printf("SpamGate launcher: update refused, restarting original %s: %v", version, err)
			child, done, err = startHealthy(ctx, o, url, version)
			if err != nil {
				return fmt.Errorf("recover original worker: %w", err)
			}
			continue
		}
		if got, e := executableVersion(o.worker); e != nil || got != newVersion {
			err = fmt.Errorf("replacement version mismatch: got %q expected %q: %v", got, newVersion, e)
		}
		if err == nil {
			record(o, "checking", newVersion, "installed "+o.worker+"; verifying process and health")
			child, done, err = startHealthy(ctx, o, url, newVersion)
		}
		if err != nil {
			if e := copyAtomic(previous, o.worker); e != nil {
				record(o, "failed", newVersion, "update failed, rollback also failed: "+e.Error())
				return fmt.Errorf("failed to recover worker after %v: %w", err, e)
			}
			failure := err
			child, done, err = startHealthy(ctx, o, url, version)
			if err != nil {
				record(o, "failed", newVersion, "rollback executable restored but previous worker did not restart: "+err.Error())
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("rolled-back worker could not restart: %w", err)
			}
			clearStaged(o)
			record(o, "rolled_back", newVersion, "replacement failed; original worker restored and restarted: "+failure.Error())
			log.Printf("SpamGate launcher: rolled back %s and verified previous worker: %v", newVersion, failure)
			continue
		}
		version = newVersion
		healthySince = time.Now()
		probeFailures = 0
		clearStaged(o)
		record(o, "healthy", version, "installed worker replaced in-place at "+o.worker+" and HTTP health version verified")
		log.Printf("SpamGate launcher: updated installed worker to %s; parent process remains alive", version)
	}
}
