//go:build !linux

package transport

import (
    "errors"
    "os"
    "path/filepath"
)

func removeQueueRecordAt(dir string, expected os.FileInfo, name string, inspected os.FileInfo) error {
    if !validQueueRecordName(name) || inspected == nil || !inspected.Mode().IsRegular() {
        return errors.New("invalid queue record removal target")
    }
    if err := checkDeliveryQueueIdentity(dir, expected); err != nil { return err }
    path := filepath.Join(dir, name)
    current, err := os.Lstat(path)
    if err != nil { return err }
    if !os.SameFile(inspected, current) || !current.Mode().IsRegular() {
        return errors.New("queue record changed before unlink")
    }
    return os.Remove(path)
}
