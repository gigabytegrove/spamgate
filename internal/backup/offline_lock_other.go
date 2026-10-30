//go:build !linux

package backup

// Non-Linux backups require the operator to stop the application first.
// Linux alone has the native .worker.lock flock interlock in this package.
func acquireOfflineLock(string) (func(), error) {
 return func(){}, nil
}
