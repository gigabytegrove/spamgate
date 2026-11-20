package main

import (
 "bytes"
 "strings"
 "testing"
)

func TestBackupOutputValidationPrecedesFilesystem(t *testing.T) {
 var output bytes.Buffer
 err := run([]string{"--operation=verify","--output=xml","--backup=/nonexistent","--manifest=/nonexistent","--key-file=/nonexistent"}, &output)
 if err == nil || !strings.Contains(err.Error(),"output must be text or json") {
  t.Fatalf("unexpected validation: %v",err)
 }
 if output.Len()!=0 {t.Fatalf("failed validation wrote result: %q",output.String())}
}

func TestBackupJSONDoesNotReportSuccessOnFailedPreflight(t *testing.T) {
 var output bytes.Buffer
 err := run([]string{"--operation=restore","--output=json","--backup=/nonexistent","--manifest=/nonexistent","--key-file=/nonexistent","--target=/opt/spamgate/data"}, &output)
 if err == nil {t.Fatal("invalid restore accepted")}
 if output.Len()!=0 {t.Fatalf("failed restore wrote success: %q",output.String())}
}
