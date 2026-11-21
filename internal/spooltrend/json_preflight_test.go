package spooltrend

import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestStrictJSONPreflight(t *testing.T) {
 for _,tc:=range []struct{name,input string;valid bool}{
  {"valid",`{"a":{"b":[1,2]},"c":true}`,true},
  {"duplicate-root",`{"a":1,"a":2}`,false},
  {"duplicate-nested",`{"a":{"b":1,"b":2}}`,false},
  {"duplicate-array-object",`[{"x":1,"x":2}]`,false},
  {"trailing",`{"a":1} {"b":2}`,false},
  {"malformed",`{"a":`,false},
  {"deep",strings.Repeat("[",65)+"0"+strings.Repeat("]",65),false},
 } {
  t.Run(tc.name,func(t *testing.T){
   err:=validateJSON([]byte(tc.input))
   if (err==nil)!=tc.valid {t.Fatalf("valid=%v err=%v",tc.valid,err)}
  })
 }
}
func TestLoadRejectsDuplicateEvidenceKeys(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"audit.json")
 base:=`{"gate_passed":true,"examined":1,"published":1,"pending":0,"states":{"queued":1},"findings":[],"truncated":false}`
 cases:=[]string{
  strings.Replace(base,`"gate_passed":true`,`"gate_passed":false,"gate_passed":true`,1),
  strings.Replace(base,`"queued":1`,`"queued":999,"queued":1`,1),
  strings.Replace(base,`"examined":1`,`"examined":0,"examined":1`,1),
  strings.Replace(base,`"states":{"queued":1}`,`"states":{"queued":1},"states":{"queued":1}`,1),
 }
 for i,body:=range cases {
  if err:=os.WriteFile(path,[]byte(body),0600);err!=nil{t.Fatal(err)}
  if _,err:=Load(path);err==nil{t.Fatalf("case %d accepted ambiguous evidence",i)}
 }
}
func TestLoadRejectsOverflowAndOversize(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"audit.json")
 for _,body:=range []string{
  fmt.Sprintf(`{"gate_passed":true,"examined":%d,"published":%d,"pending":1,"states":{},"findings":[],"truncated":false}`,int(^uint(0)>>1),int(^uint(0)>>1)),
  fmt.Sprintf(`{"gate_passed":true,"examined":%d,"published":%d,"pending":0,"states":{"queued":%d,"dead":1},"findings":[],"truncated":false}`,int(^uint(0)>>1),int(^uint(0)>>1),int(^uint(0)>>1)),
  `{"gate_passed":true,"examined":0,"published":0,"pending":0,"states":{},"findings":[],"truncated":false,"padding":"`+strings.Repeat("x",maxReportSize)+`"}`,
 }{
  if err:=os.WriteFile(path,[]byte(body),0600);err!=nil{t.Fatal(err)}
  if _,err:=Load(path);err==nil{t.Fatal("accepted invalid counts or oversized input")}
 }
}
func TestValidSnapshotJSONStillLoads(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"audit.json")
 b,_:=json.Marshal(map[string]any{"gate_passed":true,"examined":2,"published":1,"pending":1,"states":map[string]int{"queued":1},"findings":[]any{},"truncated":false,"additional_forward_compatible_field":true})
 if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
 if _,err:=Load(path);err!=nil{t.Fatal(err)}
}
