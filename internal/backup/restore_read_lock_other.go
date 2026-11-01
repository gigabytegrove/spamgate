//go:build !linux

package backup

// Non-Linux platforms have no worker flock equivalence. The caller must
// ensure the restored tree is offline and no external writers are active.
func acquireRestoreReadLock(string) (func(), func() error, error) {
 return func(){}, func() error { return nil }, nil
}
