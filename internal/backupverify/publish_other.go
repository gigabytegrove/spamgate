//go:build !linux

package backupverify

import "errors"

// No non-atomic fallback is permitted for cold restore publication.
func publishRestore(stage, target string) error {
 return errors.New("atomic no-replace restore publication requires Linux")
}
