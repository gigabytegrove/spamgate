package transport

import (
    "errors"
    "fmt"
    "os"
)

// inspectDeliveryQueueIdentity opens the directory and verifies that the
// pathname still names the opened object. A symlink or replacement must never
// be accepted as the queue's durable storage.
func inspectDeliveryQueueIdentity(path string) (os.FileInfo, error) {
    before, err := os.Lstat(path)
    if err != nil {
        return nil, fmt.Errorf("inspect delivery queue directory: %w", err)
    }
    if err := validateDeliveryQueueDirectory(before); err != nil {
        return nil, err
    }
    opened, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("open delivery queue directory: %w", err)
    }
    defer opened.Close()
    actual, err := opened.Stat()
    if err != nil {
        return nil, fmt.Errorf("stat opened delivery queue directory: %w", err)
    }
    if !os.SameFile(before, actual) {
        return nil, errors.New("delivery queue directory changed between inspection and open")
    }
    if err := validateDeliveryQueueDirectory(actual); err != nil {
        return nil, err
    }
    after, err := os.Lstat(path)
    if err != nil {
        return nil, fmt.Errorf("reinspect delivery queue directory: %w", err)
    }
    if !os.SameFile(actual, after) {
        return nil, errors.New("delivery queue directory identity changed during inspection")
    }
    if err := validateDeliveryQueueDirectory(after); err != nil {
        return nil, err
    }
    return actual, nil
}

// captureDeliveryQueueIdentity pins the opened directory object at startup.
// Pathname-based operations still require descriptor-relative hardening.
func captureDeliveryQueueIdentity(path string) (os.FileInfo, error) {
    return inspectDeliveryQueueIdentity(path)
}

// checkDeliveryQueueIdentity refuses a missing, substituted, or permission-
// drifted spool. It also checks the opened object, not merely pathname metadata.
func checkDeliveryQueueIdentity(path string, expected os.FileInfo) error {
    if expected == nil {
        return errors.New("delivery queue directory identity is not initialized")
    }
    actual, err := inspectDeliveryQueueIdentity(path)
    if err != nil {
        return fmt.Errorf("delivery queue directory is unavailable or unsafe: %w", err)
    }
    if !os.SameFile(expected, actual) {
        return errors.New("delivery queue directory identity changed after startup")
    }
    return nil
}
