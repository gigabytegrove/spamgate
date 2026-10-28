package server

import (
 "testing"
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
