package server

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
 "github.com/gigabytegrove/spamgate/internal/updater"
)

func TestStageAndCheckShareSupervisorStatus(t *testing.T) {
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 s:=New(st,nil)
 t.Setenv(updater.SupervisedEnv,"1")
 if err:=updater.Record(st.DataDir(),"healthy","v0.6.0-alpha.11","replacement responded to health check");err!=nil{t.Fatal(err)}
 status:=s.annotateUpdateStatus(updater.Status{Current:"0.6.0-alpha.10",Latest:"v0.6.0-alpha.11",Available:true,Staged:true})
 if status.InstallMode!="supervised"||status.InstallPath==""||status.LastUpdate==nil||status.LastUpdate.State!="healthy"||!status.Staged{t.Fatalf("stage lost supervisor state: %+v",status)}
 t.Setenv(updater.SupervisedEnv,"")
 status=s.annotateUpdateStatus(updater.Status{Staged:true})
 if status.InstallMode!="requires_supervisor"{t.Fatalf("unsafe install allowed: %+v",status)}
}

func TestLocalUpdateStatusReportsRealSupervisorWithoutReleaseLookup(t *testing.T) {
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{
  c.SetupComplete=true
  c.Users=append(c.Users,core.User{Name:"admin",Role:"admin"},core.User{Name:"alice",Role:"mailbox",Email:"alice@example.org"})
  return nil
 });err!=nil{t.Fatal(err)}
 s:=New(st,nil)
 s.sessions["admin-local"]=session{Identity:Identity{Name:"admin",Role:"admin",Session:true,CSRF:"a"},Expires:time.Now().Add(time.Hour)}
 s.sessions["mailbox-local"]=session{Identity:Identity{Name:"alice",Role:"mailbox",Session:true,CSRF:"b"},Expires:time.Now().Add(time.Hour)}
 t.Setenv(updater.SupervisedEnv,"1")
 t.Setenv("SPAMGATE_INSTALLED_WORKER","/opt/spamgate/spamgate-worker")
 invoke:=func(cookie string)*httptest.ResponseRecorder{
  t.Helper()
  req:=httptest.NewRequest(http.MethodGet,"/api/v1/update/status",nil)
  if cookie!=""{req.AddCookie(&http.Cookie{Name:"spamgate_session",Value:cookie})}
  w:=httptest.NewRecorder()
  s.Router().ServeHTTP(w,req)
  return w
 }
 if w:=invoke("");w.Code!=http.StatusUnauthorized{t.Fatalf("anonymous local status: %d %s",w.Code,w.Body.String())}
 if w:=invoke("mailbox-local");w.Code!=http.StatusForbidden{t.Fatalf("mailbox local status: %d %s",w.Code,w.Body.String())}
 w:=invoke("admin-local")
 if w.Code!=http.StatusOK{t.Fatalf("admin local status: %d %s",w.Code,w.Body.String())}
 var result updater.Status
 if err:=json.Unmarshal(w.Body.Bytes(),&result);err!=nil{t.Fatal(err)}
 if result.Current!=core.Version||result.InstallMode!="supervised"||result.InstallPath!="/opt/spamgate/spamgate-worker"{
  t.Fatalf("supervised local status not reported: %+v",result)
 }
 if result.Latest!=""||result.Available{t.Fatalf("local-only status falsely claimed a GitHub release check: %+v",result)}
 t.Setenv(updater.SupervisedEnv,"")
 w=invoke("admin-local")
 if w.Code!=http.StatusOK{t.Fatal(w.Code)}
 if err:=json.Unmarshal(w.Body.Bytes(),&result);err!=nil{t.Fatal(err)}
 if result.InstallMode!="requires_supervisor"{t.Fatalf("unsupervised mode hidden: %+v",result)}
}
