//go:build !linux

package main

import "errors"

// The native backup operator requires Linux descriptor semantics for private inputs.
func readPrivateFile(string, int64, int) ([]byte, error) {
 return nil, errors.New("native backup verification requires Linux")
}
