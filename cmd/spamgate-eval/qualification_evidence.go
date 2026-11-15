package main

// qualificationEvidence describes the exact integrity controls applied to an
// offline evaluation. It never includes a corpus path, raw message or identity.
// An empty corpus digest is intentionally distinguishable from a verified one.
type qualificationEvidence struct {
 Mode bool `json:"qualification_mode"`
 UniqueIDsRequired bool `json:"unique_ids_required"`
 CohortsRequired bool `json:"cohorts_required"`
 CorpusSHA256 string `json:"corpus_sha256,omitempty"`
 CorpusDigestVerified bool `json:"corpus_digest_verified"`
 EvaluatedRecords int `json:"evaluated_records"`
 MaximumInputBytes int64 `json:"maximum_input_bytes"`
 MaximumRecords int `json:"maximum_records"`
 Thresholds *qualificationThresholds `json:"thresholds,omitempty"`
 Scope string `json:"scope"`
}

func qualificationEvidenceForRun(mode, unique, cohorts bool, verifiedDigest string, records int, byteLimit int64, recordLimit int) qualificationEvidence {
 return qualificationEvidence{
  Mode:mode,UniqueIDsRequired:unique,CohortsRequired:cohorts,
  CorpusSHA256:verifiedDigest,CorpusDigestVerified:verifiedDigest!="",
  EvaluatedRecords:records,MaximumInputBytes:byteLimit,MaximumRecords:recordLimit,
  Scope:"Offline labelled-corpus evaluation only; no live mail-host or delivery qualification.",
 }
}

// qualificationThresholds records the exact acceptance configuration used in
// the report. Without it a JSON result cannot be independently interpreted:
// changing a threshold can change pass/fail without changing corpus evidence.
// These values are policy settings, never message content or identities.
type qualificationThresholds struct {
 MinimumHam int `json:"minimum_ham"`
 MinimumSpam int `json:"minimum_spam"`
 MaximumFalsePositiveUpper95 float64 `json:"maximum_false_positive_upper_95"`
 MinimumRecallLower95 float64 `json:"minimum_recall_lower_95"`
 MinimumPrecisionLower95 float64 `json:"minimum_precision_lower_95"`
 MaximumRejectFalsePositiveUpper95 float64 `json:"maximum_reject_false_positive_upper_95"`
 MaximumDisruptiveFalsePositiveUpper95 float64 `json:"maximum_disruptive_false_positive_upper_95"`
 MinimumCohortHam int `json:"minimum_cohort_ham"`
 MinimumCohortSpam int `json:"minimum_cohort_spam"`
 MaximumCohortFalsePositiveUpper95 float64 `json:"maximum_cohort_false_positive_upper_95"`
 MinimumCohortRecallLower95 float64 `json:"minimum_cohort_recall_lower_95"`
 MinimumCohortPrecisionLower95 float64 `json:"minimum_cohort_precision_lower_95"`
 MaximumCohortRejectFalsePositiveUpper95 float64 `json:"maximum_cohort_reject_false_positive_upper_95"`
 MaximumCohortDisruptiveFalsePositiveUpper95 float64 `json:"maximum_cohort_disruptive_false_positive_upper_95"`
}
