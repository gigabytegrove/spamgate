package core

import (
 "fmt"
 "regexp"
 "strings"
 "time"
)

// BuildVersion is stamped by the native build using go -ldflags -X.
// Version remains the independent source/product version.
var BuildVersion = "unversioned"

// SourceCommit records the source that produced a compiled executable.
// The runtime never guesses an unverified Git SHA.
var SourceCommit = "unknown"

var buildIDPattern = regexp.MustCompile(`^[0-9]{8}-(?:[01][0-9]|2[0-3])[a-z]?$)

// ValidBuildVersion checks the local America/New_York calendar date and hour,
// not only the characters in the identifier. A trailing letter denotes a
// separately qualified manually initiated build.
func ValidBuildVersion(id string) bool {
 if !buildIDPattern.MatchString(id) { return false }
 _, err := time.Parse("20060102", id[:8])
 return err == nil
}

// CompareBuildVersions is only used after comparing source versions.
// Numbered builds sort by Eastern calendar date and wall-clock hour. For
// the same hour, the scheduled build precedes manual a..z builds.
// An unversioned legacy binary sorts before any numbered build.
func CompareBuildVersions(a, b string) (int, error) {
 if a == b {
  if a == "unversioned" || ValidBuildVersion(a) { return 0, nil }
  return 0, fmt.Errorf("invalid build version %q", a)
 }
 if a == "unversioned" && ValidBuildVersion(b) { return -1, nil }
 if b == "unversioned" && ValidBuildVersion(a) { return 1, nil }
 if !ValidBuildVersion(a) || !ValidBuildVersion(b) {
  return 0, fmt.Errorf("invalid build version(s) %q and %q", a, b)
 }
 return strings.Compare(a, b), nil
}
