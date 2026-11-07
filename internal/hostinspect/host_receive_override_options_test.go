package hostinspect

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestReceiveOverrideOptionsNoMiltersInventory(t *testing.T) {
 cases := []struct {
  name, input string
  want []string
  incomplete bool
 }{
  {"disabled submission", "submission/inet/receive_override_options=no_milters", []string{"submission/inet/receive_override_options"}, false},
  {"mixed options", "submission/inet/receive_override_options=no_unknown_recipient_checks, no_milters", []string{"submission/inet/receive_override_options"}, false},
  {"unrelated option", "submission/inet/receive_override_options=no_address_mappings", nil, false},
  {"substring not bypass", "submission/inet/receive_override_options=not_no_milters", nil, false},
  {"non milter override", "submission/inet/smtpd_tls_security_level=encrypt", nil, false},
  {"sensitive value omitted", "submission/inet/receive_override_options=no_milters,secret_token", []string{"submission/inet/receive_override_options"}, false},
  {"unsafe service", "submission\x1b[31m/inet/receive_override_options=no_milters", nil, true},
  {"duplicate bypass", "submission/inet/receive_override_options=no_milters\nsubmission/inet/receive_override_options=no_milters", []string{"submission/inet/receive_override_options"}, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got, incomplete := InspectMilterServiceOverrides(tc.input)
   if incomplete != tc.incomplete { t.Fatalf("incomplete=%v, want %v", incomplete, tc.incomplete) }
   if len(got)!=len(tc.want) { t.Fatalf("identities=%q, want %q", got, tc.want) }
   for i := range got {
    if got[i]!=tc.want[i] { t.Fatalf("identities=%q, want %q", got, tc.want) }
    if strings.Contains(got[i],"secret") || strings.Contains(got[i],"no_milters") { t.Fatalf("configuration value leaked: %q",got[i]) }
   }
  })
 }
}

func TestReceiveOverrideOptionsNoMiltersMarksPostfixCoverageUncertain(t *testing.T) {
 root:=t.TempDir()
 path:=filepath.Join(root,"etc/postfix/main.cf")
 if err:=os.MkdirAll(filepath.Dir(path),0755);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(path,nil,0644);err!=nil {t.Fatal(err)}
 p:=Probe{
  Root:root,
  Lookup:func(name string)(string,error){if name=="postconf"{return "postconf",nil};return "",errors.New("missing")},
  Reach:func(string)bool{return true},
  Run:func(_ context.Context,_ string,args ...string)(string,error){
   if len(args)!=2 || args[0]!="-h" {t.Fatalf("unexpected args: %v",args)}
   switch args[1] {
   case "smtpd_milters","non_smtpd_milters":return LocalMilter,nil
   case "milter_default_action":return "tempfail",nil
   case "milter_protocol":return "6",nil
   case "smtpd_milter_maps":return "",nil
   }
   t.Fatalf("unexpected key: %v",args)
   return "",nil
  },
  MasterOverrides:func(context.Context)(string,error){return "submission/inet/receive_override_options=no_milters",nil},
 }
 got:=p.Detect(context.Background())
 if !got.PostfixConfigured {t.Fatalf("global Milter configuration unexpectedly missing: %+v",got)}
 if !got.PostfixCoverageUncertain {t.Fatalf("service bypass was not flagged: %+v",got)}
 if len(got.PostfixServiceMilterOverrides)!=1 || got.PostfixServiceMilterOverrides[0]!="submission/inet/receive_override_options" {t.Fatalf("missing sanitized service identity: %+v",got)}
}
