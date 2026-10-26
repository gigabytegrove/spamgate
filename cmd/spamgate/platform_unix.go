//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func runPlatform(app func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app(ctx)
}

// Non-Windows processes do not launch a browser implicitly.
func openDashboardWhenReady(context.Context, string, string) {}
func showFatalError(error)                                   {}
