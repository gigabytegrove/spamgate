package hostinspect

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestPostfixUnknownConfigurationNeverClaimsCertainCoverage(t *testing.T) {
 for _, tc := range []struct {
  name string
  failKey string
  defaultAction string
  protocol string
  wantNote string
 }{
  {"missing smtpd configuration", "smtpd_milters", "tempfail", "6", "Unable to read Postfix milter configuration"},
  {"unreadable non smtpd", "non_smtpd_milters", "tempfail", "6", "Could not inspect Postfix non_smtpd_milters"},
  {"unreadable default action", "milter_default_action", "tempfail", "6", "Could not inspect Postfix milter_default_action"},
  {"unreadable protocol", "milter_protocol", "tempfail", "6", "Could not inspect Postfix milter_protocol"},
  {"unreadable client maps", "smtpd_milter_maps", "tempfail", "6", "Could not inspect Postfix smtpd_milter_maps"},
  {"unknown fail action", "", "unknown", "6", "not confirmed fail-closed"},
  {"blank fail action", "", "", "6", "not confirmed fail-closed"},
  {"missing protocol value", "", "tempfail", "", "protocol could not be confirmed"},
  {"explicit tempfail", "", "tempfail", "6", ""},
  {"explicit reject", "", "reject", "6", ""},
 } {
  t.Run(tc.name, func(t *testing.T) {
   root := t.TempDir()
   path := filepath.Join(root, "etc/postfix/main.cf")
   if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
   if err := os.WriteFile(path, nil, 0644); err != nil { t.Fatal(err) }
   p := Probe{
    Root: root,
    Lookup: func(name string) (string, error) {
     if name == "postconf" { return "postconf", nil }
     return "", errors.New("missing")
    },
    Run: func(_ context.Context, _ string, args ...string) (string, error) {
     if len(args) != 2 || args[0] != "-h" { t.Fatalf("unexpected arguments: %v", args) }
     key := args[1]
     if key == tc.failKey { return "", errors.New("permission denied") }
     switch key {
     case "smtpd_milters", "non_smtpd_milters": return LocalMilter, nil
     case "milter_default_action": return tc.defaultAction, nil
     case "milter_protocol": return tc.protocol, nil
     case "smtpd_milter_maps": return "", nil
     default: t.Fatalf("unexpected key %q", key); return "", nil
     }
    },
    Reach: func(string) bool { return true },
    MasterOverrides: func(context.Context) (string, error) { return "", nil },
   }
   got := p.Detect(context.Background())
   if !got.PostfixConfigured && tc.failKey == "" { t.Fatalf("expected global Milter settings configured: %+v", got) }
   certain := tc.wantNote == ""
   if got.PostfixCoverageUncertain == certain {
    t.Fatalf("unexpected coverage uncertainty: %+v", got)
   }
   if tc.wantNote != "" && !strings.Contains(strings.Join(got.Notes, " | "), tc.wantNote) {
    t.Fatalf("missing note %q in %v", tc.wantNote, got.Notes)
   }
  })
 }
}
