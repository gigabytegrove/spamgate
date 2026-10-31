package server

import (
    "os"
    "runtime"
)

// syncMonitorDirectory confirms rename and directory creation durability on
// Linux. Windows directory handles do not support the same fsync contract;
// native Windows tests must qualify the platform-specific crash semantics.
func syncMonitorDirectory(path string) error {
    if runtime.GOOS == "windows" {
        return nil
    }
    dir, err := os.Open(path)
    if err != nil {
        return err
    }
    syncErr := dir.Sync()
    closeErr := dir.Close()
    if syncErr != nil {
        return syncErr
    }
    return closeErr
}
