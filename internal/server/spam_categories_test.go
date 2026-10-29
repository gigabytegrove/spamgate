package server

import(
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
 "github.com/gigabytegrove/spamgate/internal/core"
)
func TestSpamCategoryAdminEndpointsAndDryRun(t *testing.T){
 store,e:=core.Open(t.TempDir());if e!=nil{t.Fatal(e)}
 tok,hash,e:=core.MakeToken();if e!=nil{t.Fatal(e)}
 if e=store.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true
  c.Tokens=[]core.Token{{Name:"admin",Hash:hash,Scope:"admin",Created:time.Now()}}
  return nil
 });e!=nil{t.Fatal(e)}
 s:=New(store,nil)
 req:=func(method,path,key string)*httptest.ResponseRecorder{
  r:=httptest.NewRequest(method,path,nil)
  if key!=""{r.Header.Set("Authorization","Bearer "+key)}
  w:=httptest.NewRecorder();s.Router().ServeHTTP(w,r);return w
 }
 if w:=req("GET","/api/v1/spam-categories","");w.Code!=http.StatusUnauthorized{t.Fatalf("public access %d",w.Code)}
 w:=req("GET","/api/v1/spam-categories",tok)
 if w.Code!=200||!bytes.Contains(w.Body.Bytes(),[]byte("credential_theft")){t.Fatalf("catalog %d %s",w.Code,w.Body.String())}
 w=req("POST","/api/v1/spam-categories/phishing/simulate",tok)
 if w.Code!=200{t.Fatalf("lab status %d %s",w.Code,w.Body.String())}
 var result struct {
  Simulation bool `json:"simulation"`
  Persisted bool `json:"persisted"`
  MTA bool `json:"mta_verified"`
  Message core.Message `json:"message"`
 }
 if e=json.Unmarshal(w.Body.Bytes(),&result);e!=nil{t.Fatal(e)}
 if !result.Simulation||result.Persisted||result.MTA||result.Message.TestCase!="phishing"||result.Message.Action!="reject"{t.Fatalf("invalid lab result %+v",result)}
 if len(store.List(1000,""))!=0{t.Fatal("dry run persisted mail")}
 w=req("GET","/api/v1/spam-categories/credential_theft/sample.eml?recipient=sgtest@example.org",tok)
 if w.Code!=200||!strings.Contains(w.Header().Get("Content-Type"),"message/rfc822")||!bytes.Contains(w.Body.Bytes(),[]byte("SGTUBE-V1-CREDENTIAL-THEFT")){t.Fatalf("sample %d %s",w.Code,w.Body.String())}
 if w=req("GET","/api/v1/spam-categories/credential_theft/sample.eml?recipient=bad%0D%0ABcc:evil",tok);w.Code!=400{t.Fatalf("header injection %d",w.Code)}
 if w=req("GET","/api/v1/spam-categories/absent/messages",tok);w.Code!=404{t.Fatalf("unknown category %d",w.Code)}
 if w=req("GET","/api/v1/spam-categories/phishing/messages?limit=10000",tok);w.Code!=400{t.Fatalf("unbounded list %d",w.Code)}
}
