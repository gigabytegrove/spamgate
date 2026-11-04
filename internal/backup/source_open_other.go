//go:build !linux

package backup

import "os"

// Other platforms retain the existing behavior; Linux is the native beta target.
func openBackupSourceFile(path string) (*os.File, error) {
 return os.Open(path)
}
