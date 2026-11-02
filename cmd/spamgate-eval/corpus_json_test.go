package main

import (
    "bytes"
    "strings"
    "testing"
)

func TestCorpusJSONStrictSchemaAndPrivacy(t *testing.T) {
    good := []string{
        `{"label":"ham","action":"accept"}`,
        `{"label":"spam","action":"soft_reject","cohort":"direct","id":"` + strings.Repeat("a",64) + `"}`,
        `{"action":"reject","label":"spam","cohort":"","id":""}`,
    }
    for _, line := range good {
        if _, err := parseCorpusRecord([]byte(line)); err != nil {
            t.Fatalf("valid record refused: %v", err)
        }
    }
    bad := map[string]string{
        "duplicate label": `{"label":"ham","label":"spam","action":"accept"}`,
        "duplicate action": `{"label":"ham","action":"accept","action":"reject"}`,
        "casefold alias": `{"label":"ham","action":"accept","Action":"reject"}`,
        "escaped alias": `{"label":"ham","action":"accept","act\u0069on":"reject"}`,
        "unicode alias": `{"label":"ham","action":"accept","\u0061ction":"reject"}`,
        "uppercase only": `{"Label":"ham","action":"accept"}`,
        "unknown PII": `{"label":"ham","action":"accept","sender":"private@example.invalid"}`,
        "null label": `{"label":null,"action":"accept"}`,
        "null optional": `{"label":"ham","action":"accept","cohort":null}`,
        "number": `{"label":"ham","action":123}`,
        "boolean": `{"label":"ham","action":true}`,
        "array": `[{"label":"ham","action":"accept"}]`,
        "trailing": `{"label":"ham","action":"accept"}{"label":"spam","action":"reject"}`,
        "missing action": `{"label":"ham","cohort":"direct"}`,
        "missing label": `{"action":"accept","cohort":"direct"}`,
        "unpaired surrogate": `{"label":"ham","action":"accept","id":"\ud800"}`,
        "oversized": `{"label":"ham","action":"accept","cohort":"`+strings.Repeat("x",64<<10)+`"}`,
    }
    for name, line := range bad {
        t.Run(name, func(t *testing.T) {
            _, err := parseCorpusRecord([]byte(line))
            if err == nil {
                t.Fatal("ambiguous or unsafe corpus record accepted")
            }
            if strings.Contains(err.Error(), "private@example.invalid") {
                t.Fatal("parser leaked untrusted message metadata in error")
            }
        })
    }
    invalidUTF8 := append([]byte(`{"label":"ham","action":"accept","id":"`),0xff)
    invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
    if _, err := parseCorpusRecord(invalidUTF8); err == nil {
        t.Fatal("invalid UTF-8 accepted")
    }
}

func TestCorpusRejectsAmbiguousLabelsBeforeScoring(t *testing.T) {
    records := []string{
        `{"label":"ham","action":"accept"}`,
        `{"label":"spam","action":"reject"}`,
    }
    if _, err := readLabels(strings.NewReader(strings.Join(records,"\n"))); err != nil {
        t.Fatalf("legacy valid labels refused: %v", err)
    }
    for _, attack := range []string{
        `{"label":"ham","action":"accept","action":"reject"}`,
        `{"label":"ham","action":"accept","Action":"reject"}`,
        `{"label":"ham","action":"accept","sender":"private@example.invalid"}`,
    } {
        data := strings.Join(append(append([]string{},records...),attack),"\n")
        if _, err := readLabels(strings.NewReader(data)); err == nil {
            t.Fatal("ambiguous label entered confusion matrix")
        }
    }
    var output, stderr bytes.Buffer
    // Bad JSON must fail with code 2 and must not emit a misleading report.
    if code := run([]string{"--min-ham=1","--min-spam=1","--max-fpr-upper=1","--min-recall-lower=0","/nonexistent"},&output,&stderr); code != 2 {
        t.Fatalf("unexpected missing-file exit code: %d",code)
    }
}
