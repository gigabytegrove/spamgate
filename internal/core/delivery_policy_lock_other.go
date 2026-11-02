//go:build !linux

package core

import "sync"

// Non-Linux builds retain process-local serialization. Sharing one data
// directory across multiple processes is supported only on native Linux.
var localDeliveryPolicyMutex sync.Mutex

func acquireDeliveryPolicyLock(string) (func(), error) {
	localDeliveryPolicyMutex.Lock()
	return localDeliveryPolicyMutex.Unlock, nil
}
