//go:build !linux

package core

import "sync"

// Preserve existing single-process behavior on Windows and other non-Linux
// builds. Cross-process durable journal coordination is only qualified on
// native Linux; callers on other platforms must not share one data root.
var localHistoryJournalMutex sync.Mutex

func acquireHistoryWriteLock(dir string) (func(), error) {
 localHistoryJournalMutex.Lock()
 return localHistoryJournalMutex.Unlock, nil
}
