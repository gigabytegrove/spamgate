package server

import (
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestPostfixInventoryMarksTruncatedRecipients(t *testing.T) {
 var recipients []map[string]string
 for i:=0;i<55;i++ {recipients=append(recipients,map[string]string{"address":fmt.Sprintf("user%02d@example.org",i)})}
 raw,err:=json.Marshal(map[string]any{"queue_name":"hold","queue_id":"AF123","sender":"sender@example.net","arrival_time":1793100000,"recipients":recipients})
 if err!=nil{t.Fatal(err)}
 held,err:=parsePostfixHold(append(raw,'\n'))
 if err!=nil{t.Fatal(err)}
 if len(held)!=1||held[0].RecipientCount!=55||len(held[0].Recipients)!=50||!held[0].RecipientsTruncated{
  t.Fatalf("truncated inventory not marked: %+v",held)
 }
 if _,err:=parsePostfixHold([]byte(`{"queue_name":"hold","queue_id":"AF123*","recipients":[]}`));err==nil{
  t.Fatal("accepted queue identifier that cannot be safely passed to postsuper")
 }
}

func TestPostfixHoldReleaseRefusesIncompleteRecipientInventory(t *testing.T) {
 store,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=store.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true
  c.Users=[]core.User{{Name:"admin",Role:"admin"}}
  return nil
 });err!=nil{t.Fatal(err)}
 m:=core.Message{ID:core.ID(),Timestamp:time.Now().UTC(),Connector:"milter",MTAQueueID:"AF123",MTAAction:"postfix_hold_requested",Sender:"sender@example.net",Recipients:[]string{"user@example.org"},Action:"quarantine"}
 if err:=store.Save(m);err!=nil{t.Fatal(err)}
 t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY","true")
 t.Setenv("SPAMGATE_POSTFIX_HOLD_ACTIONS","true")
 srv:=New(store,nil)
 srv.sessions["admin-test"]=session{Identity:Identity{Name:"admin",Role:"admin",Session:true,CSRF:"csrf"},Expires:time.Now().Add(time.Hour)}
 held:=[]PostfixHeld{{QueueID:"AF123",Sender:m.Sender,Recipients:[]string{"user@example.org"},RecipientCount:55,RecipientsTruncated:true,ArrivalTime:m.Timestamp.Unix()}}
 srv.PostfixHeldInventory=func(context.Context)([]PostfixHeld,error){return held,nil}
 calls:=0
 srv.PostfixReleaseHeld=func(context.Context,string)(string,error){calls++;return "ok",nil}
 send:=func() *httptest.ResponseRecorder {
  req:=httptest.NewRequest("POST","/api/v1/messages/"+m.ID+"/postfix-release",strings.NewReader(`{"queue_id":"AF123","confirm":"release Postfix hold AF123","reason":"Verified false positive by administrator"}`))
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("X-CSRF-Token","csrf")
  req.AddCookie(&http.Cookie{Name:"spamgate_session",Value:"admin-test"})
  w:=httptest.NewRecorder()
  srv.Router().ServeHTTP(w,req)
  return w
 }
 if w:=send();w.Code!=http.StatusConflict{t.Fatalf("truncated recipient inventory permitted: %d %s",w.Code,w.Body.String())}
 if calls!=0{t.Fatal("release invoked with incomplete recipient inventory")}
 held[0].RecipientsTruncated=false
 if w:=send();w.Code!=http.StatusConflict{t.Fatalf("recipient count mismatch permitted: %d %s",w.Code,w.Body.String())}
 held[0].RecipientCount=1
 held=append(held,held[0])
 if w:=send();w.Code!=http.StatusConflict{t.Fatalf("duplicate queue ID permitted: %d %s",w.Code,w.Body.String())}
 if calls!=0{t.Fatal("unsafe release command executed")}
}
