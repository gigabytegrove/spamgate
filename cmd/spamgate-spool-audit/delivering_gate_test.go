package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestDeliveringLimitFailures(t *testing.T) {
 states := map[string]int{"delivering": 3, "queued": 99}
 for _, tc := range []struct {
  name string
  maximum int
  want string
 }{
  {"disabled", -1, ""},
  {"inclusive", 3, ""},
  {"over", 2, "delivering=3 exceeds max-delivering=2"},
  {"zero", 0, "delivering=3 exceeds max-delivering=0"},
 } {
  t.Run(tc.name, func(t *testing.T) {
   got := deliveringLimitFailures(states, tc.maximum)
   if tc.want == "" && len(got) != 0 { t.Fatalf("unexpected failure: %v", got) }
   if tc.want != "" && (len(got) != 1 || got[0] != tc.want) { t.Fatalf("got %v, want %q", got, tc.want) }
  })
 }
}

func TestDeliveringCLIValidation(t *testing.T) {
 dir := filepath.Join(t.TempDir(), "delivery-queue")
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 for _, tc := range []struct {
  args []string
  exit int
  contains string
 }{
  {[]string{"-dir",dir,"-max-delivering=0","-json"}, 0, "\"gate_passed\": true"},
  {[]string{"-dir",dir,"-max-delivering=-2"}, 2, "nonnegative"},
  {[]string{"-dir",dir,"-max-delivering=not-an-int"}, 2, "invalid value"},
 } {
  var out, stderr bytes.Buffer
  got := run(tc.args,&out,&stderr)
  if got != tc.exit { t.Fatalf("%v: exit %d want %d; stderr=%s",tc.args,got,tc.exit,stderr.String()) }
  if !strings.Contains(out.String()+stderr.String(),tc.contains) { t.Fatalf("%v: missing %q in output %s / %s",tc.args,tc.contains,out.String(),stderr.String()) }
 }
}
