package server

import (
 "context"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "github.com/gigabytegrove/spamgate/internal/core"
 "github.com/gigabytegrove/spamgate/internal/transport"
)
func TestMetricsQueueCorruptionCannotDisappearSilently(t *testing.T){
 st,err:=core.Open(t.TempDir());if err!=nil{t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config)error{c.SetupComplete=true;c.Users=[]core.User{{Name:"admin",Role:"admin"}};return nil});err!=nil{t.Fatal(err)}
 s:=New(st,nil)
 s.sessions["admin"]=session{Identity:Identity{Name:"admin",Role:"admin",Session:true},Expires:time.Now().Add(time.Hour)}
 q,err:=transport.NewDeliveryQueue(st.DataDir(),st,func(context.Context,core.Message,[]byte)error{return nil});if err!=nil{t.Fatal(err)}
 s.Queue=q
 read:=func()string{
  req:=httptest.NewRequest(http.MethodGet,"/api/v1/metrics",nil)
  req.AddCookie(&http.Cookie{Name:"spamgate_session",Value:"admin"})
  w:=httptest.NewRecorder();s.Router().ServeHTTP(w,req)
  if w.Code!=200{t.Fatalf("metrics HTTP %d",w.Code)}
  return w.Body.String()
 }
 healthy:=read()
 if !strings.Contains(healthy,"spamgate_outbox_snapshot_available 1")||!strings.Contains(healthy,"spamgate_outbox_snapshot_error 0"){t.Fatalf("healthy metrics: %s",healthy)}
 if err:=os.WriteFile(filepath.Join(st.DataDir(),"delivery-queue","corrupt.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 damaged:=read()
 if !strings.Contains(damaged,"spamgate_outbox_snapshot_available 0")||!strings.Contains(damaged,"spamgate_outbox_snapshot_error 1"){t.Fatalf("corrupt queue hidden: %s",damaged)}
 if strings.Contains(damaged,"spamgate_outbox_messages{status="){t.Fatal("stale outbox counts published after integrity failure")}
}
