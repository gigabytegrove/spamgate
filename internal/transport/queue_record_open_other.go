//go:build !linux

package transport

import (
    "os"
    "path/filepath"
)

// Non-Linux builds retain the existing validated pathname read.
func readQueueRecordAt(dir string, expected os.FileInfo, name string, inspected os.FileInfo) ([]byte, error) {
    if err := checkDeliveryQueueIdentity(dir, expected); err != nil { return nil, err }
    return readSpoolFile(filepath.Join(dir, name), inspected)
}
