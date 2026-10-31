//go:build !linux

package server

import (
	"context"
	"errors"
)

// Postfix release is Linux-only until an equivalent cross-process ownership
// lock and a supported native Postfix installation are qualified.
func acquirePostfixHoldReleaseLock(_ context.Context, _ string) (func(), error) {
	return nil, errors.New("Postfix hold release requires the native Linux lock implementation")
}
