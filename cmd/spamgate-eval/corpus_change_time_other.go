//go:build !linux

package main

import "os"

// Non-Linux systems retain existing size/mtime/inode checks. Linux is the
// native production target and additionally checks inode change time.
func evaluationCorpusChangeTimeEqual(before, after os.FileInfo) bool {
 return true
}
