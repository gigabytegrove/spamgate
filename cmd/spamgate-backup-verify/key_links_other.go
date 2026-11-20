//go:build !linux

package main

import "os"

// Native cold restore is Linux-only. Portable verification still enforces
// same-inode key/manifest separation via os.SameFile.
func checkPrivateKeyLinks(_ os.FileInfo) error { return nil }
