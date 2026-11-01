package core

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// BuildVersion is stamped by native builds using go -ldflags -X.
// It never changes the separate source version constant.
var BuildVersion = "unversioned"

// SourceCommit identifies the exact checkout used for this executable.
var SourceCommit = "unknown"

var buildIDPattern = regexp.MustCompile("^[0-9]{8}-(?:[01][0-9]|2[0-3])[a-z]?$")

// ValidBuildVersion rejects impossible dates and out-of-range hours.
func ValidBuildVersion(id string) bool {
	if !buildIDPattern.MatchString(id) {
		return false
	}
	_, err := time.Parse("20060102", id[:8])
	return err == nil
}

// CompareBuildVersions compares Eastern-hour slots, with automatic builds
// before manual a..z revisions within the same wall-clock hour.
// A pre-numbering executable is older than all numbered releases.
func CompareBuildVersions(a, b string) (int, error) {
	if a == b {
		if a == "unversioned" || ValidBuildVersion(a) {
			return 0, nil
		}
		return 0, fmt.Errorf("invalid build version %q", a)
	}
	if a == "unversioned" && ValidBuildVersion(b) {
		return -1, nil
	}
	if b == "unversioned" && ValidBuildVersion(a) {
		return 1, nil
	}
	if !ValidBuildVersion(a) || !ValidBuildVersion(b) {
		return 0, fmt.Errorf("invalid build versions %q and %q", a, b)
	}
	return strings.Compare(a, b), nil
}
