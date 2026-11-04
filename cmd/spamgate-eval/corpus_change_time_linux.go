//go:build linux

package main

import (
 "os"
 "syscall"
)

// Linux ctime changes on content writes and metadata changes even when an
// actor restores the original mtime and size. It is not a cryptographic
// integrity guarantee; --corpus-sha256 remains the evidence integrity gate.
func evaluationCorpusChangeTimeEqual(before, after os.FileInfo) bool {
 a,okA:=before.Sys().(*syscall.Stat_t)
 b,okB:=after.Sys().(*syscall.Stat_t)
 if !okA || !okB { return false }
 return a.Ctim.Sec==b.Ctim.Sec && a.Ctim.Nsec==b.Ctim.Nsec
}
