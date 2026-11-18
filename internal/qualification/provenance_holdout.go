package qualification

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProvenanceRecord is externally supplied evidence about a labeled message.
// FamilyID must identify related messages (including near-duplicates and
// forwarded variants); ContentSHA256 must be a lowercase SHA-256 hex digest.
// This metadata is untrusted until independently audited against source mail.
type ProvenanceRecord struct {
	SampleID string `json:"sample_id"`
	Tenant string `json:"tenant"`
	FamilyID string `json:"family_id"`
	ContentSHA256 string `json:"content_sha256"`
	ObservedAt time.Time `json:"observed_at"`
}

// ProvenanceHoldoutQualification adds a chronological, message-family and
// exact-content separation gate to the existing frozen-threshold qualification.
// It does not assert that supplied provenance is independently authenticated.
type ProvenanceHoldoutQualification struct {
	HoldoutQualification
	TuningLatest time.Time `json:"tuning_latest"`
	HoldoutEarliest time.Time `json:"holdout_earliest"`
}

// ValidateHoldoutProvenance refuses to qualify corpora with reused message
// families, identical content, absent metadata, or a non-chronological split.
// It also requires one provenance record per sample, matching tenant and ID.
func ValidateHoldoutProvenance(tuning, holdout []Sample, tuningRecords, holdoutRecords []ProvenanceRecord) (time.Time, time.Time, error) {
	if len(tuning) == 0 || len(holdout) == 0 {
		return time.Time{}, time.Time{}, errors.New("both corpora must be nonempty")
	}
	if err := ValidateIndependentHoldout(tuning, holdout); err != nil {
		return time.Time{}, time.Time{}, err
	}
	seenFamilies := make(map[string]struct{})
	seenDigests := make(map[string]struct{})
	// Reject duplicate evidence within either corpus as well as cross-corpus leakage.
	// Otherwise repeated copies can artificially narrow confidence intervals.
	corpusFamilies := make(map[string]struct{})
	corpusDigests := make(map[string]struct{})
	latest := time.Time{}
	earliest := time.Time{}
	validate := func(samples []Sample, records []ProvenanceRecord, isTuning bool) error {
		if len(samples) != len(records) {
			return errors.New("provenance count must match sample count")
		}
		clear(corpusFamilies)
		clear(corpusDigests)
		byID := make(map[string]Sample, len(samples))
		for _, sample := range samples {
			byID[sample.ID] = sample
		}
		seenIDs := make(map[string]struct{}, len(records))
		for _, record := range records {
			sample, ok := byID[record.SampleID]
			if !ok || record.Tenant != sample.Tenant {
				return fmt.Errorf("provenance sample or tenant mismatch: %q", record.SampleID)
			}
			if _, exists := seenIDs[record.SampleID]; exists {
				return fmt.Errorf("duplicate provenance ID: %q", record.SampleID)
			}
			seenIDs[record.SampleID] = struct{}{}
			if record.FamilyID == "" || strings.TrimSpace(record.FamilyID) != record.FamilyID {
				return fmt.Errorf("invalid family ID for %q", record.SampleID)
			}
			if !validSHA256(record.ContentSHA256) {
				return fmt.Errorf("invalid SHA-256 for %q", record.SampleID)
			}
			if _, exists := corpusFamilies[record.FamilyID]; exists {
				return fmt.Errorf("repeated message family within corpus: %q", record.SampleID)
			}
			if _, exists := corpusDigests[record.ContentSHA256]; exists {
				return fmt.Errorf("repeated message content within corpus: %q", record.SampleID)
			}
			corpusFamilies[record.FamilyID] = struct{}{}
			corpusDigests[record.ContentSHA256] = struct{}{}
			if record.ObservedAt.IsZero() {
				return fmt.Errorf("missing observation time for %q", record.SampleID)
			}
			if isTuning {
				seenFamilies[record.FamilyID] = struct{}{}
				seenDigests[record.ContentSHA256] = struct{}{}
				if record.ObservedAt.After(latest) {
					latest = record.ObservedAt
				}
			} else {
				if _, exists := seenFamilies[record.FamilyID]; exists {
					return errors.New("holdout shares a tuning message family")
				}
				if _, exists := seenDigests[record.ContentSHA256]; exists {
					return errors.New("holdout shares tuning message content")
				}
				if earliest.IsZero() || record.ObservedAt.Before(earliest) {
					earliest = record.ObservedAt
				}
			}
		}
		return nil
	}
	if err := validate(tuning, tuningRecords, true); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if err := validate(holdout, holdoutRecords, false); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !latest.Before(earliest) {
		return latest, earliest, errors.New("holdout must start strictly after all tuning observations")
	}
	return latest, earliest, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// QualifyProvenanceHoldout validates supplied provenance before evaluating a
// frozen threshold. No production policy is changed by this advisory API.
func QualifyProvenanceHoldout(tuning, holdout []Sample, tuningRecords, holdoutRecords []ProvenanceRecord, thresholds []float64, fp GateConfig, precision PrecisionGateConfig, recall RecallGateConfig) (ProvenanceHoldoutQualification, error) {
	latest, earliest, err := ValidateHoldoutProvenance(tuning, holdout, tuningRecords, holdoutRecords)
	if err != nil {
		return ProvenanceHoldoutQualification{}, err
	}
	report, err := QualifyIndependentHoldout(tuning, holdout, thresholds, fp, precision, recall)
	if err != nil {
		return ProvenanceHoldoutQualification{}, err
	}
	return ProvenanceHoldoutQualification{HoldoutQualification: report, TuningLatest: latest, HoldoutEarliest: earliest}, nil
}
