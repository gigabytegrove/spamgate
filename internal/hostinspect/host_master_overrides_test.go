package hostinspect

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestHasMilterServiceOverrides(t *testing.T) {
 for _, tc := range []struct{name, input string; want bool}{
  {"empty", "", false},
  {"unrelated", "submission/inet/smtpd_tls_security_level=encrypt\nsmtp/inet/syslog_name=postfix/smtp", false},
  {"disabled submission", "submission/inet/smtpd_milters=", true},
  {"override protocol", "smtp/inet/milter_protocol=6", true},
  {"override failure action", "submission/inet/milter_default_action=accept", true},
  {"client map", "smtp/inet/smtpd_milter_maps=cidr:/etc/postfix/maps", true},
  {"non smtp", "pickup/unix/non_smtpd_milters=", true},
  {"not substring", "smtp/inet/my_smtpd_milters=none", false},
 } {
  t.Run(tc.name,func(t *testing.T) {
   if got:=HasMilterServiceOverrides(tc.input);got!=tc.want { t.Fatalf("got %v, want %v",got,tc.want) }
  })
 }
}

func TestPostfixServiceOverrideCoverage(t *testing.T) {
 for _, tc := range []struct{name, output string; err error; uncertain bool; note string}{
  {"no overrides", "submission/inet/smtpd_tls_security_level=encrypt",nil,false,""},
  {"submission bypass", "submission/inet/smtpd_milters=",nil,true,"master.cf contains"},
  {"read failure", "",errors.New("permission denied"),true,"Could not inspect Postfix master.cf"},
 } {
  t.Run(tc.name,func(t *testing.T) {
   root:=t.TempDir()
   path:=filepath.Join(root,"etc/postfix/main.cf")
   if err:=os.MkdirAll(filepath.Dir(path),0755);err!=nil {t.Fatal(err)}
   if err:=os.WriteFile(path,nil,0644);err!=nil {t.Fatal(err)}
   p:=Probe{
    Root:root,
    Lookup:func(name string)(string,error){if name=="postconf"{return "postconf",nil};return "",errors.New("missing")},
    Reach:func(string)bool{return true},
    Run:func(_ context.Context,_ string,args ...string)(string,error){
     if len(args)!=2 || args[0]!="-h"{t.Fatalf("unexpected args: %v",args)}
     switch args[1] {
     case "smtpd_milters","non_smtpd_milters":return LocalMilter,nil
     case "milter_default_action":return "tempfail",nil
     case "milter_protocol":return "6",nil
     case "smtpd_milter_maps":return "",nil
     }
     t.Fatalf("unexpected key: %v",args);return "",nil
    },
    MasterOverrides:func(context.Context)(string,error){return tc.output,tc.err},
   }
   got:=p.Detect(context.Background())
   if got.PostfixCoverageUncertain!=tc.uncertain {t.Fatalf("uncertainty=%v want %v: %+v",got.PostfixCoverageUncertain,tc.uncertain,got)}
   if tc.note!="" && !strings.Contains(strings.Join(got.Notes," | "),tc.note){t.Fatalf("missing %q in %v",tc.note,got.Notes)}
  })
 }
}
