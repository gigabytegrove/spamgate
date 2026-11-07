package transport

import (
    "errors"
    "fmt"
    "os"
)

// openVerifiedDeliveryQueueDirectory retains the descriptor used for the
// operation, rather than checking one descriptor and then reopening the path.
// This narrows substitution windows for directory inventory and fsync. It does
// not make pathname-based child operations descriptor-relative.
func openVerifiedDeliveryQueueDirectory(path string, expected os.FileInfo) (*os.File, error) {
    if expected == nil {
        return nil, errors.New("delivery queue directory identity is not initialized")
    }
    before, err := os.Lstat(path)
    if err != nil { return nil, fmt.Errorf("inspect delivery queue directory: %w", err) }
    if err := validateDeliveryQueueDirectory(before); err != nil { return nil, err }
    if !os.SameFile(expected, before) {
        return nil, errors.New("delivery queue directory identity changed after startup")
    }
    dir, err := os.Open(path)
    if err != nil { return nil, fmt.Errorf("open delivery queue directory: %w", err) }
    fail := func(err error) (*os.File, error) { _ = dir.Close(); return nil, err }
    opened, err := dir.Stat()
    if err != nil { return fail(fmt.Errorf("stat opened delivery queue directory: %w", err)) }
    if err := validateDeliveryQueueDirectory(opened); err != nil { return fail(err) }
    if !os.SameFile(expected, opened) || !os.SameFile(before, opened) {
        return fail(errors.New("delivery queue directory changed between inspection and open"))
    }
    after, err := os.Lstat(path)
    if err != nil { return fail(fmt.Errorf("reinspect delivery queue directory: %w", err)) }
    if err := validateDeliveryQueueDirectory(after); err != nil { return fail(err) }
    if !os.SameFile(expected, after) || !os.SameFile(opened, after) {
        return fail(errors.New("delivery queue directory identity changed during open"))
    }
    return dir, nil
}
