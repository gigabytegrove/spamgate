package server

import (
 "bytes"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestHistoryIntegrityAdminOnlyAndReadOnly(t *testing.T) {
 store,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 token,hash,err:=core.MakeToken();if err!=nil{t.Fatal(err)}
 if err:=store.UpdateConfig(func(c *core.Config) error{
  c.SetupComplete=true
  c.Tokens=[]core.Token{{Name:"operations",Hash:hash,Scope:"admin",Created:time.Now()}}
  return nil
 });err!=nil{t.Fatal(err)}
 msg:=core.Message{ID:core.ID(),Timestamp:time.Now().UTC(),Action:"quarantine",Sender:"private@example.org",Recipients:[]string{"secret@example.org"}}
 if err:=store.Save(msg);err!=nil{t.Fatal(err)}
 router:=New(store,nil).Router()
 request:=func(path,auth string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(http.MethodGet,path,nil)
  if auth!=""{req.Header.Set("Authorization","Bearer "+auth)}
  w:=httptest.NewRecorder();router.ServeHTTP(w,req);return w
 }
 if got:=request("/api/v1/history/integrity","");got.Code!=401{t.Fatalf("unauthenticated history audit: %d",got.Code)}
 if got:=request("/api/v1/history/integrity",token);got.Code!=200||!bytes.Contains(got.Body.Bytes(),[]byte("\"disk_events\":1"))||bytes.Contains(got.Body.Bytes(),[]byte("private@example.org"))||bytes.Contains(got.Body.Bytes(),[]byte("secret@example.org")){
  t.Fatalf("history audit response %d %s",got.Code,got.Body.String())
 }
}
