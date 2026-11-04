//go:build !linux

package main

import "os"

// Non-Linux builds retain the existing identity and regular-file checks.
func openEvaluationCorpusDescriptor(path string) (*os.File, error) {
    return os.Open(path)
}
