package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"encoding/json"
	"github.com/gigabytegrove/spamgate/internal/backup"
	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/hostinspect"
	"github.com/gigabytegrove/spamgate/internal/server"
	"github.com/gigabytegrove/spamgate/internal/transport"
	"github.com/gigabytegrove/spamgate/internal/updater"
)

type options struct {
	dataDir string
	listen  string
	logFile string
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		// An interactive first run must not require administrator privileges.
		// The Windows Service installer explicitly passes -data ProgramData\SpamGate.
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "SpamGate")
		}
		if base, err := os.UserConfigDir(); err == nil {
			return filepath.Join(base, "SpamGate")
		}
		return "SpamGate-data"
	}
	return "/var/lib/spamgate"
}

func defaultListen() string {
	if value := os.Getenv("SPAMGATE_WEB_LISTEN"); value != "" {
		return value
	}
	// The web dashboard is reachable via the host's interfaces by default.
	// Mail-facing listeners are separate and remain disabled unless configured,
	// with loopback-only addresses in the local Postfix setup instructions.
	return "0.0.0.0:38470"
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		if errors.Is(err, errUpdateRestart) {
			os.Exit(updater.UpdateRestartExitCode)
		}
		slog.Error("SpamGate stopped", "error", err)
		showFatalError(err)
		os.Exit(1)
	}
}

var errUpdateRestart = errors.New("verified update requires supervisor restart")

func supervisorDataDir(args []string) string {
	dir := defaultDataDir()
	for i := 0; i < len(args); i++ {
		if args[i] == "-data" && i+1 < len(args) {
			dir = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "-data=") {
			dir = strings.TrimPrefix(args[i], "-data=")
		}
	}
	return dir
}
func execute(args []string) error {
	if len(args) > 0 && args[0] == "-internal-supervise" {
		childArgs := args[1:]
		if os.Getenv(updater.SupervisedEnv) == "1" {
			return errors.New("nested SpamGate supervisor not allowed")
		}
		return runPlatform(func(ctx context.Context) error {
			return updater.Supervise(ctx, childArgs, supervisorDataDir(childArgs))
		})
	}
	if len(args) == 2 && args[0] == "-internal-update-apply" {
		return updater.ApplyFromHelper(args[1])
	}
	flags := flag.NewFlagSet("spamgate", flag.ContinueOnError)
	data := flags.String("data", defaultDataDir(), "Persistent data directory")
	web := flags.String("listen", defaultListen(), "Management HTTP listener (use an HTTPS reverse proxy for remote access)")
	logPath := flags.String("log-file", "", "Optional append-only application log (useful for Windows services)")
	logLevel := flags.String("log-level", os.Getenv("SPAMGATE_LOG_LEVEL"), "Logging verbosity: debug, info (default), warn, error")
	version := flags.Bool("version", false, "Print version")
	backupFile := flags.String("backup-file", "", "Offline backup: write a ZIP of the stopped SpamGate data directory to a new file")
	verifyBackup := flags.String("verify-backup", "", "Verify SHA-256 hashes and structure of an offline backup ZIP")
	restoreBackup := flags.String("restore-backup", "", "Restore a verified backup ZIP to a new, nonexistent -data directory (server must be stopped)")
	mailReport := flags.Bool("mailserver-report", false, "Read-only report of local MTA and hosting-panel integration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *version {
		fmt.Println(core.Version)
		return nil
	}
	if *mailReport {
		return json.NewEncoder(os.Stdout).Encode(hostinspect.Detect(context.Background()))
	}
	if (*backupFile != "" && *verifyBackup != "") || (*backupFile != "" && *restoreBackup != "") || (*verifyBackup != "" && *restoreBackup != "") {
		return fmt.Errorf("choose only one offline backup operation")
	}
	if *backupFile != "" {
		if err := backup.Create(*data, *backupFile); err != nil {
			return err
		}
		fmt.Println("SpamGate offline backup written:", *backupFile)
		return nil
	}
	if *verifyBackup != "" {
		manifest, err := backup.Verify(*verifyBackup)
		if err != nil {
			return err
		}
		fmt.Printf("SpamGate backup verified: %d file(s), created %s\n", len(manifest.Entries), manifest.Created.Format(time.RFC3339))
		return nil
	}
	if *restoreBackup != "" {
		if err := backup.Restore(*restoreBackup, *data); err != nil {
			return err
		}
		fmt.Println("SpamGate backup restored to:", *data)
		return nil
	}
	if *data == "" || *web == "" {
		return fmt.Errorf("data and listen must not be empty")
	}
	// A GUI-subsystem EXE has no terminal. Persist startup failures and the one-time
	// setup key for the interactive user without a script or administrator rights.
	if *logPath == "" && runtime.GOOS == "windows" {
		*logPath = filepath.Join(*data, "logs", "spamgate.log")
	}
	level := slog.LevelInfo
	switch *logLevel {
	case "", "info":
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q: choose debug, info, warn or error", *logLevel)
	}
	output := io.Writer(os.Stderr)
	if *logPath != "" {
		if err := os.MkdirAll(filepath.Dir(*logPath), 0700); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
		f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open application log: %w", err)
		}
		defer f.Close()
		output = io.MultiWriter(os.Stderr, f)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: level})))
	return runPlatform(func(ctx context.Context) error {
		return runApp(ctx, options{dataDir: *data, listen: *web, logFile: *logPath})
	})
}

func runApp(ctx context.Context, opts options) error {
	// Exclusive Linux writer ownership prevents two workers from compacting
	// the same events.jsonl with divergent in-memory history.
	unlock, err := acquireInstanceLock(opts.dataDir)
	if err != nil { return err }
	defer unlock()
	store, err := core.Open(opts.dataDir)
	if err != nil {
		return err
	}
	relay, err := transport.RelayFromEnv()
	if err != nil {
		return err
	}
	inbound, err := transport.SMTPFromEnv(store, relay)
	if err != nil {
		return err
	}
	var queue *transport.DeliveryQueue
	if relay != nil && os.Getenv("SPAMGATE_DURABLE_QUEUE") != "false" {
		// Resume persisted jobs even if the SMTP intake listener is disabled.
		queue, err = transport.NewDeliveryQueue(opts.dataDir, store, relay.Send)
		if err != nil {
			return fmt.Errorf("initialize SMTP delivery spool: %w", err)
		}
		if inbound != nil {
			inbound.Queue = queue
		}
	}
	rspamdWorker, err := transport.RspamdFromEnv(store)
	if err != nil {
		return err
	}
	controller, err := transport.ControllerFromEnv(store)
	if err != nil {
		return err
	}
	milterWorker, err := transport.MilterFromEnv(store)
	if err != nil {
		return err
	}
	seen := map[string]string{opts.listen: "management"}
	listeners := []struct{ address, name string }{}
	if rspamdWorker != nil {
		listeners = append(listeners, struct{ address, name string }{rspamdWorker.ListenAddress, "rspamd-http"})
	}
	if controller != nil {
		listeners = append(listeners, struct{ address, name string }{controller.ListenAddress, "rspamd-controller"})
	}
	if milterWorker != nil {
		listeners = append(listeners, struct{ address, name string }{milterWorker.Addr, "milter"})
	}
	if inbound != nil {
		listeners = append(listeners, struct{ address, name string }{inbound.Addr, "smtp"})
	}
	for _, listener := range listeners {
		if previous, exists := seen[listener.address]; exists {
			return fmt.Errorf("listener collision: %s and %s both use %s", previous, listener.name, listener.address)
		}
		seen[listener.address] = listener.name
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := server.New(store, nil)
	if relay != nil {
		srv.Deliver = relay.Send
	}
	srv.Queue = queue
	restartRequested := make(chan struct{}, 1)
	srv.UpdateExit = func() {
		go func() {
			time.Sleep(350 * time.Millisecond)
			select {
			case restartRequested <- struct{}{}:
			default:
			}
		}()
	}
	srv.Runtime = server.RuntimeStatus{
		RelayConfigured: relay != nil,
		Services: map[string]server.RuntimeService{
			"management":  {Enabled: true, Address: opts.listen, Detail: "Management HTTP listener configured"},
			"rspamd_http": {Enabled: rspamdWorker != nil, Detail: "Rspamd-compatible HTTP scan listener configured"},
			"milter":      {Enabled: milterWorker != nil, Detail: "Milter listener configured"},
			"smtp":        {Enabled: inbound != nil, Detail: "SMTP filter listener configured"},
			"controller":  {Enabled: controller != nil, Detail: "Rspamd-compatible controller configured"},
		},
	}
	if rspamdWorker != nil {
		x := srv.Runtime.Services["rspamd_http"]
		x.Address = rspamdWorker.ListenAddress
		srv.Runtime.Services["rspamd_http"] = x
	}
	if milterWorker != nil {
		x := srv.Runtime.Services["milter"]
		x.Address = milterWorker.Addr
		srv.Runtime.Services["milter"] = x
	}
	if inbound != nil {
		x := srv.Runtime.Services["smtp"]
		x.Address = inbound.Addr
		srv.Runtime.Services["smtp"] = x
	}
	if controller != nil {
		x := srv.Runtime.Services["controller"]
		x.Address = controller.ListenAddress
		srv.Runtime.Services["controller"] = x
	}

	errorsCh := make(chan error, 5)
	go func() { errorsCh <- srv.ListenAndServe(ctx, opts.listen) }()
	// Interactive Windows launches use the native GUI subsystem, without a CMD
	// console. The browser opens only after the real local health check passes.
	openDashboardWhenReady(ctx, opts.listen, srv.SetupClaimKey())
	if rspamdWorker != nil {
		go func() { errorsCh <- rspamdWorker.Listen(ctx) }()
	}
	if milterWorker != nil {
		go func() { errorsCh <- milterWorker.Listen(ctx) }()
	}
	if controller != nil {
		go func() { errorsCh <- controller.Listen(ctx) }()
	}
	if inbound != nil {
		go func() { errorsCh <- inbound.Listen(ctx) }()
	}
	if queue != nil {
		go queue.Run(ctx)
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case err := <-errorsCh:
			cancel()
			return err
		case <-restartRequested:
			cancel()
			return errUpdateRestart
		case <-ticker.C:
			if err := store.Compact(); err != nil {
				slog.Error("history compaction failed", "error", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}
