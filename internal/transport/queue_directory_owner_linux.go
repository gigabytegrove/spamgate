//go:build linux

package transport

import (
    "errors"
    "os"
    "syscall"
)

// The native worker must own its private spool. Root can otherwise read or
// overwrite a different service account's 0700 queue, hiding an unsafe
// ownership drift during upgrades. No automatic chown is performed.
func validateDeliveryQueueOwner(info os.FileInfo) error {
    if info == nil {
        return errors.New("delivery queue metadata is missing")
    }
    stat, ok := info.Sys().(*syscall.Stat_t)
    if !ok {
        return errors.New("delivery queue ownership could not be verified")
    }
    if stat.Uid != uint32(os.Geteuid()) {
        return errors.New("delivery queue owner differs from effective worker UID; inspect ownership before changing it")
    }
    return nil
}
