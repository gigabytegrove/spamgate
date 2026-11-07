package transport

import (
    "errors"
    "fmt"
    "os"
)

// validateDeliveryQueueDirectoryPath verifies the opened directory, not just
// metadata obtained before opening. In particular, a symlink swap between
// lstat and open must not redirect the worker into an unrelated directory.
// No permissions or ownership are modified.
func validateDeliveryQueueDirectoryPath(path string) error {
    inspected, err := os.Lstat(path)
    if err != nil { return fmt.Errorf("inspect delivery queue directory: %w", err) }
    if err := validateDeliveryQueueDirectory(inspected); err != nil { return err }
    opened, err := os.Open(path)
    if err != nil { return fmt.Errorf("open delivery queue directory: %w", err) }
    defer opened.Close()
    actual, err := opened.Stat()
    if err != nil { return fmt.Errorf("stat opened delivery queue directory: %w", err) }
    if !os.SameFile(inspected, actual) {
        return errors.New("delivery queue directory changed between inspection and open")
    }
    if err := validateDeliveryQueueDirectory(actual); err != nil { return err }
    return nil
}
