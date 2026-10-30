package server

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPostfixHoldReleaseCorrelatesNullReversePath(t *testing.T) {
 store,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=store.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true
  c.Users=[]core.User{{Name:"admin",Role:"admin"}}
  return nil
 });err!=nil{t.Fatal(err)}
 msg:=core.Message{
  ID:core.ID(),Timestamp:time.Now().UTC(),Connector:"milter",
  MTAQueueID:"ACED1234",MTAAction:"postfix_hold_requested",
  Sender:"",Recipients:[]string{"recipient@example.org"},Action:"quarantine",
 }
 if err:=store.Save(msg);err!=nil{t.Fatal(err)}
 t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY","true")
 t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS","true")
 srv:=New(store,nil)
 srv.sessions["null-sender-admin"]=session{
  Identity:Identity{Name:"admin",Role:"admin",Session:true,CSRF:"csrf"},
  Expires:time.Now().Add(time.Hour),
 }
 held:=[]PostfixHeld{{
  QueueID:msg.MTAQueueID,Sender:"bounce@example.net",
  Recipients:[]string{"recipient@example.org"},RecipientCount:1,
  ArrivalTime:msg.Timestamp.Unix(),
 }}
 srv.PostfixHeldInventory=func(context.Context)([]PostfixHeld,error){return held,nil}
 called:=0
 srv.PostfixReleaseHeld=func(context.Context,string)(string,error){called++;return "released",nil}
 request:=func() *httptest.ResponseRecorder {
  req:=httptest.NewRequest(http.MethodPost,"/api/v1/messages/"+msg.ID+"/postfix-release",
   strings.NewReader(`{"queue_id":"ACED1234","confirm":"release Postfix hold ACED1234","reason":"Verified legitimate delivery status notification"}`))
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("X-CSRF-Token","csrf")
  req.AddCookie(&http.Cookie{Name:"spamgate_session",Value:"null-sender-admin"})
  w:=httptest.NewRecorder()
  srv.Router().ServeHTTP(w,req)
  return w
 }
 if w:=request();w.Code!=http.StatusConflict{
  t.Fatalf("released null-sender scan against non-null held sender: %d %s",w.Code,w.Body.String())
 }
 if called!=0{t.Fatal("invoked postsuper for mismatched null sender")}
 held[0].Sender=""
 if w:=request();w.Code!=http.StatusAccepted{
  t.Fatalf("refused exactly correlated null-sender DSN hold: %d %s",w.Code,w.Body.String())
 }
 if called!=1{t.Fatalf("expected exactly one postsuper invocation, got %d",called)}
 saved,ok:=store.Get(msg.ID)
 if !ok||saved.MTAActionState!="release_submitted"||saved.Delivery!="postfix_release_submitted"{
  t.Fatalf("missing durable release audit: %+v %v",saved,ok)
 }
 if w:=request();w.Code!=http.StatusConflict{
  t.Fatalf("duplicate release accepted after durable audit: %d %s",w.Code,w.Body.String())
 }
 if called!=1{t.Fatal("duplicate postsuper invocation")}
}
