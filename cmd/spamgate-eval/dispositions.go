package main

// addDispositionCounts records delivery-disrupting actions separately from
// harmless tagging. Each message contributes to at most one action bucket.
func addDispositionCounts(c *counts, label, action string) {
 switch action {
 case "reject":
  if label=="ham" { c.RejectedHam++ } else { c.RejectedSpam++ }
 case "quarantine":
  if label=="ham" { c.QuarantinedHam++ } else { c.QuarantinedSpam++ }
 case "soft_reject":
  if label=="ham" { c.SoftRejectedHam++ } else { c.SoftRejectedSpam++ }
 }
}
