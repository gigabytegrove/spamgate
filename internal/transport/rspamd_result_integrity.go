package transport

import (
 "errors"
 "math"

 "github.com/gigabytegrove/spamgate/internal/core"
)

var errRspamdInvalidScanResult = errors.New("scanner produced non-finite scoring data")

// Reject non-finite values before durable history is written or an MTA is
// told to accept a message. encoding/json rejects NaN/Inf after the fact,
// which otherwise leaves an ambiguous response and potentially saved history.
func rspamdValidateScanResult(msg core.Message, cfg core.Config) error {
 finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
 if !finite(msg.Score) || !finite(cfg.Settings.TagThreshold) ||
  !finite(cfg.Settings.QuarantineThreshold) || !finite(cfg.Settings.RejectThreshold) {
  return errRspamdInvalidScanResult
 }
 for _, f := range msg.Findings {
  if !finite(f.Score) { return errRspamdInvalidScanResult }
 }
 if msg.Scoring != nil {
  if !finite(msg.Scoring.TagThreshold) || !finite(msg.Scoring.QuarantineThreshold) ||
   !finite(msg.Scoring.RejectThreshold) { return errRspamdInvalidScanResult }
 }
 for _, c := range msg.Categories {
  _ = c
 }
 return nil
}
