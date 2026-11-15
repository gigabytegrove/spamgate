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
