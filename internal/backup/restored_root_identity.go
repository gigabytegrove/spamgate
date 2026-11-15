package backup

import (
    "fmt"
    "os"
)

// verifyRestoredRootIdentity detects a destination pathname replaced during
// offline verification. This is a final identity check, not a substitute for
// stopping writers and restricting access to parent directories.
func verifyRestoredRootIdentity(root string, initial os.FileInfo) error {
    current, err := os.Lstat(root)
    if err != nil {
        return fmt.Errorf("restored data root disappeared during verification: %w", err)
    }
    if !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(initial, current) {
        return fmt.Errorf("restored data root changed during verification")
    }
    return nil
}
