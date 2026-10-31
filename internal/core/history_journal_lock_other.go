//go:build !linux

package core

import "errors"

// No unqualified cross-process history writes on other platforms.
func acquireHistoryWriteLock(dir string)(func(),error){
 return nil,errors.New("native shared history locking is supported only on Linux")
}
