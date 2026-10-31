//go:build !linux

package transport

import (
	"context"
	"errors"
)

// Cross-process delivery serialization requires the native Linux flock
// implementation. Refuse delivery on unsupported platforms rather than
// silently claiming protection while allowing duplicate relay workers.
var ErrDeliveryWorkerBusy = errors.New("delivery queue already has an active worker")

func acquireDeliveryWorkerLock(ctx context.Context, dir string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("cross-process delivery worker lock is supported only on Linux")
}

// Non-Linux native builds cannot claim safe shared SMTP intake publication.
var ErrDeliveryIntakeBusy = errors.New("delivery queue intake lock is busy")

func acquireDeliveryIntakeLock(ctx context.Context, dir string) (func(), error) {
	if err := ctx.Err(); err != nil { return nil, err }
	return nil, errors.New("cross-process delivery intake lock is supported only on Linux")
}
