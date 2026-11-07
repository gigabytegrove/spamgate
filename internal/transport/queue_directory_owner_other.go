//go:build !linux

package transport

import "os"

// Non-Linux installations retain their existing platform-specific directory
// checks. Linux native deployment additionally enforces effective UID ownership.
func validateDeliveryQueueOwner(info os.FileInfo) error {
    return nil
}
