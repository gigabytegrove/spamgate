package spooltrend

import (
 "errors"
 "fmt"
 "time"
)

// FreshnessPolicy controls evidence chronology. Zero disables a bound.
// RequireTimestamps refuses legacy reports whose capture order is unknowable.
type FreshnessPolicy struct {
 RequireTimestamps bool
 MaxSnapshotAge time.Duration
 MaxSnapshotGap time.Duration
}

// Validate checks limits without accessing a live mail queue.
func (p FreshnessPolicy) Validate() error {
 if p.MaxSnapshotAge < 0 || p.MaxSnapshotGap < 0 {
  return errors.New("snapshot age and gap must be nonnegative")
 }
 return nil
}

// CheckFreshness validates timestamps using a caller-supplied clock for deterministic tests.
// It never asserts that timestamps authenticate report provenance.
func CheckFreshness(before, after Snapshot, p FreshnessPolicy, now time.Time) error {
 if err := p.Validate(); err != nil { return err }
 if before.CapturedAt.IsZero() || after.CapturedAt.IsZero() {
  if p.RequireTimestamps || p.MaxSnapshotAge > 0 || p.MaxSnapshotGap > 0 {
   return errors.New("timestamped evidence required by freshness policy")
  }
  return nil
 }
 if !after.CapturedAt.After(before.CapturedAt) {
  return errors.New("later capture must follow earlier capture")
 }
 if after.CapturedAt.After(now.Add(5*time.Minute)) || before.CapturedAt.After(now.Add(5*time.Minute)) {
  return errors.New("capture timestamp is in the future")
 }
 if p.MaxSnapshotAge > 0 && now.Sub(after.CapturedAt) > p.MaxSnapshotAge {
  return fmt.Errorf("later evidence age %s exceeds maximum %s", now.Sub(after.CapturedAt), p.MaxSnapshotAge)
 }
 if p.MaxSnapshotGap > 0 && after.CapturedAt.Sub(before.CapturedAt) > p.MaxSnapshotGap {
  return fmt.Errorf("capture gap %s exceeds maximum %s", after.CapturedAt.Sub(before.CapturedAt), p.MaxSnapshotGap)
 }
 return nil
}
