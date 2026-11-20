//go:build linux

package main

import (
 "errors"
 "os"
 "syscall"
)

// A private authentication key with multiple directory entries can be
// smuggled into an otherwise isolated backup through a hard link.
func checkPrivateKeyLinks(info os.FileInfo) error {
 st, ok := info.Sys().(*syscall.Stat_t)
 if !ok { return errors.New("cannot inspect authentication key link count") }
 if st.Nlink != 1 { return errors.New("authentication key must have exactly one hard link") }
 return nil
}
