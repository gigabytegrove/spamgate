package qualification

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func provenanceFixture(samples []Sample, day int) []ProvenanceRecord {
	out := make([]ProvenanceRecord, 0, len(samples))
	for _, sample := range samples {
		sum := sha256.Sum256([]byte(sample.ID))
		out = append(out, ProvenanceRecord{
			SampleID: sample.ID, Tenant: sample.Tenant,
			FamilyID: "family-" + sample.ID,
			ContentSHA256: fmt.Sprintf("%x", sum),
			ObservedAt: time.Date(2026, 11, day, 12, 0, 0, 0, time.UTC),
		})
	}
	return out
}

func TestProvenanceHoldoutFrozenThreshold(t *testing.T) {
	tuning := holdoutSamples("tuning", []string{"a", "b"}, 0.1, 0.9)
	holdout := holdoutSamples("holdout", []string{"a", "b"}, 0.2, 0.8)
	fp, precision, recall := holdoutGates()
	report, err := QualifyProvenanceHoldout(tuning, holdout, provenanceFixture(tuning, 1), provenanceFixture(holdout, 2), []float64{0.5, 0.95}, fp, precision, recall)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed || report.Holdout == nil || report.Tuning.Selected == nil {
		t.Fatalf("unexpected qualification: %+v", report)
	}
	if !report.TuningLatest.Before(report.HoldoutEarliest) {
		t.Fatal("chronological boundary not recorded")
	}
}

func TestProvenanceHoldoutRejectsLeakage(t *testing.T) {
	tuning := holdoutSamples("tuning", []string{"a"}, 0.1, 0.9)
	holdout := holdoutSamples("holdout", []string{"a"}, 0.2, 0.8)
	tuneRecords := provenanceFixture(tuning, 1)
	holdRecords := provenanceFixture(holdout, 2)
	cases := []struct {
		name string
		change func([]ProvenanceRecord, []ProvenanceRecord)
	}{
		{"repeated tuning family", func(a, b []ProvenanceRecord) { a[1].FamilyID = a[0].FamilyID }},
		{"repeated tuning content", func(a, b []ProvenanceRecord) { a[1].ContentSHA256 = a[0].ContentSHA256 }},
		{"repeated holdout family", func(a, b []ProvenanceRecord) { b[1].FamilyID = b[0].FamilyID }},
		{"repeated holdout content", func(a, b []ProvenanceRecord) { b[1].ContentSHA256 = b[0].ContentSHA256 }},
		{"family leakage", func(a, b []ProvenanceRecord) { b[0].FamilyID = a[0].FamilyID }},
		{"content leakage", func(a, b []ProvenanceRecord) { b[0].ContentSHA256 = a[0].ContentSHA256 }},
		{"same day", func(a, b []ProvenanceRecord) { b[0].ObservedAt = a[0].ObservedAt }},
		{"older holdout", func(a, b []ProvenanceRecord) { b[0].ObservedAt = a[0].ObservedAt.Add(-time.Hour) }},
		{"missing time", func(a, b []ProvenanceRecord) { b[0].ObservedAt = time.Time{} }},
		{"invalid digest", func(a, b []ProvenanceRecord) { b[0].ContentSHA256 = "abc" }},
		{"uppercase digest", func(a, b []ProvenanceRecord) { b[0].ContentSHA256 = fmt.Sprintf("%X", sha256.Sum256([]byte("x"))) }},
		{"missing family", func(a, b []ProvenanceRecord) { b[0].FamilyID = "" }},
		{"tenant mismatch", func(a, b []ProvenanceRecord) { b[0].Tenant = "other" }},
		{"unknown ID", func(a, b []ProvenanceRecord) { b[0].SampleID = "unknown" }},
		{"duplicate ID", func(a, b []ProvenanceRecord) { b[1].SampleID = b[0].SampleID }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := append([]ProvenanceRecord(nil), tuneRecords...)
			b := append([]ProvenanceRecord(nil), holdRecords...)
			tc.change(a, b)
			if _, _, err := ValidateHoldoutProvenance(tuning, holdout, a, b); err == nil {
				t.Fatal("accepted invalid holdout provenance")
			}
		})
	}
}

func TestProvenanceHoldoutRejectsMissingRecordsAndOverlappingIDs(t *testing.T) {
	tuning := []Sample{{ID: "t", Tenant: "a", Score: 0.1}}
	holdout := []Sample{{ID: "h", Tenant: "a", Score: 0.9, Spam: true}}
	a := provenanceFixture(tuning, 1)
	b := provenanceFixture(holdout, 2)
	if _, _, err := ValidateHoldoutProvenance(tuning, holdout, a, nil); err == nil {
		t.Fatal("accepted missing records")
	}
	holdout[0].ID = "t"
	if _, _, err := ValidateHoldoutProvenance(tuning, holdout, a, b); err == nil {
		t.Fatal("accepted overlapping sample IDs")
	}
}
