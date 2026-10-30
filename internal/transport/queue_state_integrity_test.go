package transport

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestQueueMutableStateTamperFailsClosed(t *testing.T) {
 for _, tc := range []struct{name,key string; value any}{
  {"premature_delivery", "state", "delivered"},
  {"forced_dead_letter", "state", "dead"},
  {"backoff_manipulation", "next_attempt", "2099-01-01T00:00:00Z"},
  {"attempts_reset", "attempts", float64(99)},
  {"error_rewrite", "last_error", "fake successful relay"},
 } {
  t.Run(tc.name,func(t *testing.T){
   dir:=t.TempDir()
   store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
   sends:=0
   q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{sends++;return nil})
   if err!=nil{t.Fatal(err)}
   m:=core.Message{ID:core.ID(),Timestamp:time.Now().UTC(),Sender:"sender@example.org",Recipients:[]string{"recipient@example.net"},Action:"accept"}
   if err:=q.Enqueue(m,[]byte("From: sender@example.org\r\n\r\nOriginal"));err!=nil{t.Fatal(err)}
   path:=q.path(m.ID)
   raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
   var obj map[string]any
   if err:=json.Unmarshal(raw,&obj);err!=nil{t.Fatal(err)}
   if obj["state_sha256"]==""{t.Fatal("missing state integrity digest")}
   obj[tc.key]=tc.value
   modified,err:=json.Marshal(obj);if err!=nil{t.Fatal(err)}
   if err:=os.WriteFile(path,modified,0600);err!=nil{t.Fatal(err)}
   if _,err:=q.Snapshot();err==nil||!strings.Contains(err.Error(),"delivery-state integrity"){t.Fatalf("state corruption accepted: %v",err)}
   if err:=q.ProcessDue(context.Background());err==nil{t.Fatal("processed corrupt spool")}
   if sends!=0{t.Fatal("sent corrupt spool")}
  })
 }
}

func TestLegacyQueueStateDigestMigratesOnNextWrite(t *testing.T) {
 dir:=t.TempDir()
 store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil})
 if err!=nil{t.Fatal(err)}
 m:=core.Message{ID:core.ID(),Timestamp:time.Now().UTC(),Sender:"a@example.org",Recipients:[]string{"b@example.net"}}
 if err:=q.Enqueue(m,[]byte("legacy"));err!=nil{t.Fatal(err)}
 raw,err:=os.ReadFile(q.path(m.ID));if err!=nil{t.Fatal(err)}
 var obj map[string]any
 if err:=json.Unmarshal(raw,&obj);err!=nil{t.Fatal(err)}
 delete(obj,"state_sha256")
 old,err:=json.Marshal(obj);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(q.path(m.ID),old,0600);err!=nil{t.Fatal(err)}
 restarted,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil})
 if err!=nil{t.Fatalf("legacy spool rejected: %v",err)}
 if err:=restarted.Retry(m.ID);err!=nil{t.Fatal(err)}
 rec,err:=restarted.get(m.ID);if err!=nil{t.Fatal(err)}
 if rec.StateSHA256==""{t.Fatal("state digest not created during legacy rewrite")}
}

func TestQueueStartupRejectsDirectoryMasqueradingAsJob(t *testing.T) {
 dir:=t.TempDir()
 store,err:=core.Open(dir);if err!=nil{t.Fatal(err)}
 q,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil})
 if err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(filepath.Join(q.dir,core.ID()+".json"),0700);err!=nil{t.Fatal(err)}
 if _,err:=q.Snapshot();err==nil{t.Fatal("hidden spool directory ignored")}
 if _,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil});err==nil{t.Fatal("startup ignored unsafe queue entry")}
}
