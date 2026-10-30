//go:build !linux

package main

import (
 "errors"
 "runtime"
)

// Native Linux is the qualified mail-host runtime for this single-writer lock.
// Do not claim exclusive ownership on other platforms before implementing an
// equivalent OS file lock. Windows service mode requires its own qualification.
func acquireInstanceLock(dir string) (func(), error) {
 if runtime.GOOS == "windows" {
  // Windows service supervision already owns lifecycle; this helper does not
  // provide a cross-process lock. Fail closed for new multi-process use unless
  // service runtime is specifically handling serialization elsewhere.
  return func(){}, nil
 }
 return nil, errors.New("history writer lock is not supported on this operating system")
}
