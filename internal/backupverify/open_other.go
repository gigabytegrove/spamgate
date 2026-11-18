//go:build !linux

package backupverify

import (
 "errors"
 "os"
)

// Non-Linux platforms cannot provide the required descriptor-relative
// no-follow guarantees. Fail closed instead of claiming safe verification.
func openVerifiedPath(root, relative string) (*os.File, error) {
 return nil, errors.New("secure backup verification requires Linux")
}
