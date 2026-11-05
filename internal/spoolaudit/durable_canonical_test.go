package spoolaudit

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestDurableCanonicalKeys(t *testing.T) {
 for _, canonical := range durableRecordJSONKeys {
  t.Run(canonical, func(t *testing.T) {
   for _, alias := range []string{strings.ToUpper(canonical), strings.ToUpper(canonical[:1]) + canonical[1:]} {
    if alias == canonical { continue }
    for _, input := range []string{
     `{"` + alias + `":null}`,
     `{"` + canonical + `":1,"` + alias + `":2}`,
     `{"` + alias + `":2,"` + canonical + `":1}`,
    } {
     if err := validateDurableCanonicalKeys([]byte(input)); err == nil {
      t.Fatalf("accepted noncanonical alias %q in %s", alias, input)
     }
    }
   }
  })
 }
}

func TestDurableCanonicalKeysUnicodeAndCompatibility(t *testing.T) {
 cases := []struct {name, input string; valid bool}{
  {"canonical", `{"id":"x","sender":"","recipients":[],"scan":null}`, true},
  {"unknown extension", `{"id":"x","future_extension":true}`, true},
  {"case sensitive unknown", `{"future_extension":1,"FUTURE_EXTENSION":2}`, true},
  {"unicode escaped alias", `{"id":"x","\\u0049D":"y"}`, false},
  {"nonobject", `[]`, false},
  {"null", `null`, false},
  {"broken", `{`, false},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=validateDurableCanonicalKeys([]byte(tc.input))
   if (err==nil)!=tc.valid {t.Fatalf("valid=%t err=%v",tc.valid,err)}
  })
 }
 encoded,err:=json.Marshal(map[string]any{"sender":"","id":"x"})
 if err!=nil {t.Fatal(err)}
 if err:=validateDurableCanonicalKeys(encoded);err!=nil {t.Fatal(err)}
}

func TestAuditRejectsNoncanonicalDurableAliasWithoutLeakingPrivateEnvelope(t *testing.T) {
 dir:=privateDir(t)
 original:=fixture(idA)
 raw,err:=json.Marshal(original)
 if err!=nil {t.Fatal(err)}
 // The valid canonical sender is followed by an alternate-case sender.
 // Go struct decoding would otherwise replace the validated sender.
 private:="private-victim@example.invalid"
 injected:=strings.TrimSuffix(string(raw),"}")+`,"Sender":"`+private+`"}`
 path:=filepath.Join(dir,idA+".json")
 if err:=os.WriteFile(path,[]byte(injected),0600);err!=nil {t.Fatal(err)}
 report,err:=Audit(dir)
 if err!=nil {t.Fatal(err)}
 if report.UnreadableRecords!=1||!hasCode(report,"unreadable_record") {
  t.Fatalf("noncanonical durable field accepted: %+v",report)
 }
 encoded,err:=json.Marshal(report)
 if err!=nil {t.Fatal(err)}
 if strings.Contains(string(encoded),private) {t.Fatal("audit report leaked injected address")}
 if !strings.Contains(string(encoded),"invalid durable envelope metadata") {
  t.Fatalf("missing actionable diagnostic category: %s",encoded)
 }
}
