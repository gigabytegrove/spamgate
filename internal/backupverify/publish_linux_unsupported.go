//go:build linux && !amd64 && !arm64

package backupverify

import "errors"

func publishRestore(stage, target string) error {
 return errors.New("atomic no-replace restore publication unsupported on this Linux architecture")
}
