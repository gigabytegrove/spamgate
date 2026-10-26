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
