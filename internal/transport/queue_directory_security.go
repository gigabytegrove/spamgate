package transport

import (
    "errors"
    "os"
)

// validateDeliveryQueueDirectory requires an existing spool to be usable only
// by its owner. Read and execute are necessary for recovery inventory; write
// and execute are necessary for durable publication. Refuse special mode bits
// rather than relying on a permissive root process to bypass permissions.
// Never chmod an existing production directory automatically.
func validateDeliveryQueueDirectory(info os.FileInfo) error {
    if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
        return errors.New("delivery queue must be a real directory")
    }
    mode := info.Mode()
    if mode.Perm() != 0700 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
        return errors.New("delivery queue requires private owner read/write/search permissions (0700) without special mode bits; inspect ownership before changing permissions")
    }
    return nil
}
