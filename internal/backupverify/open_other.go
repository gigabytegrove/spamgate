//go:build !linux

package backupverify

import "os"

func openRegularNoFollow(name string)(*os.File,error){return os.Open(name)}
