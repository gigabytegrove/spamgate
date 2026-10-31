//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	deliveryWorkerLockName = ".delivery-worker.lock"
	deliveryIntakeLockName = ".delivery-intake.lock"
)

// ErrDeliveryWorkerBusy means another native worker currently owns the
// shared spool's delivery lease. It is not a mail failure or a reason to
// change the Postfix disposition.
var ErrDeliveryWorkerBusy = errors.New("delivery queue already has an active worker")

// ErrDeliveryIntakeBusy means another process is modifying the durable intake
// inventory. SMTP callers must return a temporary failure, never acknowledge.
var ErrDeliveryIntakeBusy = errors.New("delivery queue intake lock is busy")

// acquireDeliveryWorkerLock holds an advisory Linux flock across an entire
// ProcessDue pass, including the upstream SMTP acknowledgement and durable
// completion. It prevents two SpamGate worker processes using one data root
// from relaying the same queued original concurrently. Never unlink the lock
// file: an unlinked inode could allow two independent locks on one spool.
func acquireDeliveryWorkerLock(ctx context.Context, dir string) (func(), error) {
	return acquireDeliveryLease(ctx, dir, deliveryWorkerLockName, 300*time.Millisecond, ErrDeliveryWorkerBusy)
}

// A short, separate lease protects the capacity check and publication across
// independent SMTP intake processes. It never waits for an upstream SMTP relay.
func acquireDeliveryIntakeLock(ctx context.Context, dir string) (func(), error) {
	return acquireDeliveryLease(ctx, dir, deliveryIntakeLockName, 2*time.Second, ErrDeliveryIntakeBusy)
}

func acquireDeliveryLease(ctx context.Context, dir, name string, timeout time.Duration, busy error) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect delivery spool directory: %w", err)
	}
	if !root.IsDir() || root.Mode()&os.ModeSymlink != 0 || root.Mode().Perm()&0022 != 0 {
		return nil, errors.New("delivery spool directory must be a real directory without group/world write access")
	}
	path := filepath.Join(dir, name)
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open safe delivery worker lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("cannot construct delivery worker lock handle")
	}
	closeOnError := func(err error) (func(), error) { _ = file.Close(); return nil, err }
	opened, err := file.Stat()
	if err != nil {
		return closeOnError(err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return closeOnError(err)
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) || opened.Mode().Perm() != 0600 {
		return closeOnError(errors.New("delivery worker lock must be an unchanged private regular file"))
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return closeOnError(err)
	}
	if stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return closeOnError(errors.New("delivery worker lock must have one link and be owned by the worker"))
	}
	// Contention is bounded; SMTP intake must not wait for a slow upstream
	// relay held by a different worker. A later 15-second tick can retry.
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return closeOnError(err)
		}
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// Recheck the path after obtaining the lock, so a replaced lock
			// inode is never silently accepted as the shared lease.
			current, statErr := os.Lstat(path)
			if statErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				return closeOnError(errors.New("delivery worker lock changed during acquisition"))
			}
			var once sync.Once
			return func() { once.Do(func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }) }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return closeOnError(fmt.Errorf("acquire delivery worker lock: %w", err))
		}
		select {
		case <-ctx.Done():
			return closeOnError(ctx.Err())
		case <-deadline.C:
			return closeOnError(busy)
		case <-ticker.C:
		}
	}
}
