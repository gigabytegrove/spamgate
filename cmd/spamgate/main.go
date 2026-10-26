package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/server"
	"github.com/gigabytegrove/spamgate/internal/transport"
)

func main() {
	if e := run(); e != nil {
		slog.Error("SpamGate stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	data := flag.String("data", "/var/lib/spamgate", "Data directory")
	web := flag.String("listen", "0.0.0.0:8080", "Web listener")
	version := flag.Bool("version", false, "Print version")
	flag.Parse()
	if *version {
		fmt.Println(core.Version)
		return nil
	}
	store, e := core.Open(*data)
	if e != nil {
		return e
	}
	relay, e := transport.RelayFromEnv()
	if e != nil {
		return e
	}
	inbound, e := transport.SMTPFromEnv(store, relay)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := server.New(store, nil)
	if relay != nil {
		srv.Deliver = relay.Send
	}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- srv.ListenAndServe(ctx, *web) }()
	if inbound != nil {
		go func() { errorsCh <- inbound.Listen(ctx) }()
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case e := <-errorsCh:
			stop()
			if e != nil {
				return e
			}
			return nil
		case <-ticker.C:
			if e := store.Compact(); e != nil {
				slog.Error("history compaction failed", "error", e)
			}
		case <-ctx.Done():
			return nil
		}
	}
}
