//go:build linux

package server

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

const postfixHoldReleaseLockName = ".postfix-hold-release.lock"

// acquirePostfixHoldReleaseLock serializes destructive Postfix release
// requests across native SpamGate processes sharing one persistent data root.
// This is advisory: other applications and manual postsuper commands do not
// participate. The caller must retain the lock until the command and audit
// have finished. A persistent empty lock file is intentional.
func acquirePostfixHoldReleaseLock(ctx context.Context, dataDir string) (func(), error) {
	root, err := os.Lstat(dataDir)
	if err != nil {
		return nil, fmt.Errorf("inspect SpamGate data directory: %w", err)
	}
	if !root.IsDir() || root.Mode()&os.ModeSymlink != 0 || root.Mode().Perm()&0022 != 0 {
		return nil, errors.New("SpamGate data directory must be a real directory without group/world write access")
	}
	path := filepath.Join(dataDir, postfixHoldReleaseLockName)
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open safe Postfix release lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("cannot construct Postfix release lock handle")
	}
	closeOnError := func(err error) (func(), error) {
		_ = file.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		return closeOnError(err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return closeOnError(err)
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(opened, current) || opened.Mode().Perm() != 0600 {
		return closeOnError(errors.New("Postfix release lock must be an unchanged, private regular file"))
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return closeOnError(err)
	}
	if stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return closeOnError(errors.New("Postfix release lock must have one link and be owned by the worker"))
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := waitCtx.Err(); err != nil {
			return closeOnError(fmt.Errorf("Postfix release lock unavailable: %w", err))
		}
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = syscall.Flock(fd, syscall.LOCK_UN)
					_ = file.Close()
				})
			}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return closeOnError(fmt.Errorf("lock Postfix release operation: %w", err))
		}
		select {
		case <-waitCtx.Done():
			return closeOnError(fmt.Errorf("Postfix release lock unavailable: %w", waitCtx.Err()))
		case <-time.After(25 * time.Millisecond):
		}
	}
}
