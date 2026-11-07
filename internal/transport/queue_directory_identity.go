package transport

import (
    "errors"
    "fmt"
    "os"
)

// captureDeliveryQueueIdentity pins the directory object accepted at startup.
// This is an additional fail-closed check, not a replacement for descriptor-
// relative openat/renameat operations in a future filesystem hardening pass.
func captureDeliveryQueueIdentity(path string) (os.FileInfo, error) {
    if err := validateDeliveryQueueDirectoryPath(path); err != nil {
        return nil, err
    }
    info, err := os.Lstat(path)
    if err != nil {
        return nil, fmt.Errorf("inspect delivery queue identity: %w", err)
    }
    if err := validateDeliveryQueueDirectory(info); err != nil {
        return nil, err
    }
    return info, nil
}

// checkDeliveryQueueIdentity refuses a directory path that has been replaced
// since startup. Never create or repair a missing/replaced directory here:
// doing so would silently redirect previously accepted SMTP originals.
func checkDeliveryQueueIdentity(path string, expected os.FileInfo) error {
    if expected == nil {
        return errors.New("delivery queue directory identity is not initialized")
    }
    current, err := os.Lstat(path)
    if err != nil {
        return fmt.Errorf("delivery queue directory is unavailable: %w", err)
    }
    if !os.SameFile(expected, current) {
        return errors.New("delivery queue directory identity changed after startup")
    }
    if err := validateDeliveryQueueDirectory(current); err != nil {
        return fmt.Errorf("delivery queue directory became unsafe: %w", err)
    }
    return nil
}
