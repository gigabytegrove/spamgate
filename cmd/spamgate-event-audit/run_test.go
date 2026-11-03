package main

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

type failingWriter struct{}
func (failingWriter) Write([]byte) (int,error) { return 0,errors.New("injected output failure") }

func writeAuditFixture(t *testing.T, contents string) string {
 t.Helper()
 path := filepath.Join(t.TempDir(), "events.jsonl")
 if err := os.WriteFile(path, []byte(contents), 0600); err != nil { t.Fatal(err) }
 return path
}

func TestAuditCLIExitCodesAndEvidence(t *testing.T) {
 tests := []struct {
  name, contents string
  wantCode int
  wantWarning string
  wantTotal string
 }{
  {"clean", "{\"connector\":\"milter\",\"action\":\"accept\",\"score\":0}\n", 0, "", "\"total\": 1"},
  {"malformed", "{\"connector\":\"milter\",\"action\":\"accept\"}\nnot-json\n", 1, "malformed event records", "\"malformed\": 1"},
  {"unconfirmed-hold", "{\"connector\":\"milter\",\"action\":\"quarantine\"}\n", 1, "not independent evidence of Postfix hold", "\"unconfirmed_quarantine\": 1"},
  {"both", "bad\n{\"connector\":\"milter\",\"action\":\"quarantine\"}\n", 1, "malformed event records", "\"unconfirmed_quarantine\": 1"},
  {"unrelated", "{\"connector\":\"smtp\",\"action\":\"quarantine\"}\n", 0, "", "\"total\": 0"},
 }
 for _, tt := range tests {
  t.Run(tt.name, func(t *testing.T) {
   path := writeAuditFixture(t, tt.contents)
   var out, stderr bytes.Buffer
   code := run([]string{"-events",path,"-json"}, &out, &stderr)
   if code != tt.wantCode || !strings.Contains(out.String(),tt.wantTotal) || !strings.Contains(stderr.String(),tt.wantWarning) {
    t.Fatalf("exit=%d stdout=%q stderr=%q",code,out.String(),stderr.String())
   }
  })
 }
}

func TestAuditCLIRejectsBadArgumentsAndMissingInput(t *testing.T) {
 for _, args := range [][]string{{"-badflag"},{"unexpected"},{"-events",filepath.Join(t.TempDir(),"missing")}} {
  var out, stderr bytes.Buffer
  if code := run(args,&out,&stderr); code != 2 { t.Fatalf("args=%v exit=%d stderr=%s",args,code,stderr.String()) }
 }
}

func TestAuditCLIReportsOutputFailures(t *testing.T) {
 path := writeAuditFixture(t, "{\"connector\":\"milter\",\"action\":\"accept\"}\n")
 for _, args := range [][]string{{"-events",path,"-json"},{"-events",path}} {
  var stderr bytes.Buffer
  if code := run(args,failingWriter{},&stderr); code != 2 || !strings.Contains(stderr.String(),"write audit") {
   t.Fatalf("args=%v exit=%d stderr=%s",args,code,stderr.String())
  }
 }
}
