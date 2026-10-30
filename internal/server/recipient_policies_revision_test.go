package server

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"
 "github.com/gigabytegrove/spamgate/internal/core"
)
func TestRecipientPoliciesRevisionRejectsStaleAdminEdits(t *testing.T){
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 token,hash,err:=core.MakeToken();if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true;c.Tokens=[]core.Token{{Name:"admin",Hash:hash,Scope:"admin",Created:time.Now()}};return nil
 });err!=nil{t.Fatal(err)}
 router:=New(st,nil).Router()
 call:=func(method,path string,payload any)*httptest.ResponseRecorder{
  t.Helper();var b []byte;if payload!=nil{b,_=json.Marshal(payload)}
  req:=httptest.NewRequest(method,path,bytes.NewReader(b));req.Header.Set("Authorization","Bearer "+token)
  w:=httptest.NewRecorder();router.ServeHTTP(w,req);return w
 }
 var initial struct{Revision string `json:"recipient_policies_revision"`}
 w:=call("GET","/api/v1/config",nil)
 if w.Code!=200{t.Fatalf("config %d: %s",w.Code,w.Body.String())}
 if err:=json.Unmarshal(w.Body.Bytes(),&initial);err!=nil{t.Fatal(err)}
 if initial.Revision!=recipientPoliciesRevision(nil){t.Fatal("initial revision mismatch")}
 alice:=core.RecipientPolicy{Mailbox:"alice@example.org",TagThreshold:2,QuarantineThreshold:5,RejectThreshold:10}
 bob:=core.RecipientPolicy{Mailbox:"bob@example.org",TagThreshold:3,QuarantineThreshold:6,RejectThreshold:12}
 if w:=call("PUT","/api/v1/recipient-policies",map[string]any{"policies":[]core.RecipientPolicy{alice}});w.Code!=400{t.Fatalf("missing revision accepted: %d",w.Code)}
 if w:=call("PUT","/api/v1/recipient-policies",map[string]any{"expected_revision":initial.Revision,"policies":[]core.RecipientPolicy{alice}});w.Code!=200{t.Fatalf("first write %d: %s",w.Code,w.Body.String())}
 if w:=call("PUT","/api/v1/recipient-policies",map[string]any{"expected_revision":initial.Revision,"policies":[]core.RecipientPolicy{bob}});w.Code!=http.StatusConflict{t.Fatalf("stale write %d: %s",w.Code,w.Body.String())}
 if p:=st.Config().RecipientPolicies;len(p)!=1||p[0].Mailbox!=alice.Mailbox{t.Fatalf("lost update: %+v",p)}
 var refreshed struct{Revision string `json:"recipient_policies_revision"`}
 w=call("GET","/api/v1/config",nil)
 if err:=json.Unmarshal(w.Body.Bytes(),&refreshed);err!=nil{t.Fatal(err)}
 if refreshed.Revision==initial.Revision{t.Fatal("revision did not change")}
 if w:=call("PUT","/api/v1/recipient-policies",map[string]any{"expected_revision":refreshed.Revision,"policies":[]core.RecipientPolicy{alice,bob}});w.Code!=200{t.Fatalf("refreshed write %d: %s",w.Code,w.Body.String())}
 if len(st.Config().RecipientPolicies)!=2{t.Fatal("refreshed policies not persisted")}
 if recipientPoliciesRevision([]core.RecipientPolicy{bob,alice})!=recipientPoliciesRevision([]core.RecipientPolicy{alice,bob}){t.Fatal("display order changed revision")}
}
