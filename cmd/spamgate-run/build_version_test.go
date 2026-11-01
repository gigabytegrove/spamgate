package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestLauncherComparesIndependentBuildVersions(t *testing.T) {
 cases:=[]struct{a,b string; want int}{
  {"v0.6.0-beta.2+20261101-01","0.6.0-beta.2",1},
  {"v0.6.0-beta.2+20261101-01a","0.6.0-beta.2+20261101-01",1},
  {"v0.6.0-beta.2+20261101-01z","0.6.0-beta.2+20261101-02",-1},
  {"v0.6.0-beta.3","v0.6.0-beta.2+20261101-23z",1},
  {"v0.6.0-beta.2+20261101-01","v0.6.0-beta.2+20261101-01",0},
 }
 for _,tc:=range cases {
  got,err:=compareVersions(tc.a,tc.b)
  if err!=nil||got!=tc.want{t.Errorf("%q vs %q got %d (%v), want %d",tc.a,tc.b,got,err,tc.want)}
 }
 for _,v:=range []string{"v0.6.0-beta.2+20261101-24","v0.6.0-beta.2+20260230-01","v0.6.0-beta.2+20261101-01A"} {
  if _,err:=compareVersions(v,"v0.6.0-beta.2");err==nil{t.Errorf("accepted invalid build: %q",v)}
 }
}

func TestLauncherStagesSourceUnchangedWithNumberedBuild(t *testing.T) {
 folder:=t.TempDir()
 o:=options{data:folder,worker:filepath.Join(folder,"spamgate-worker")}
 if err:=os.MkdirAll(updateFolder(o),0700);err!=nil{t.Fatal(err)}
 binary:=[]byte(strings.Repeat("RELEASE_WORKER_",500))
 sum:=sha256.Sum256(binary)
 manifest:=updateManifest{Version:"v0.6.0-beta.2+20261101-01a",Filename:"spamgate-worker-linux-amd64",SHA256:hex.EncodeToString(sum[:])}
 raw,_:=json.Marshal(manifest)
 if err:=os.WriteFile(filepath.Join(updateFolder(o),"pending.json"),raw,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(updateFolder(o),"pending"),binary,0700);err!=nil{t.Fatal(err)}
 path,got,err:=staged(o)
 if err!=nil||got!="0.6.0-beta.2+20261101-01a"||path==""{t.Fatalf("staged got %q (%v): %v",got,path,err)}
 manifest.Version="v0.6.0-beta.2+20261101-24"
 raw,_=json.Marshal(manifest)
 if err:=os.WriteFile(filepath.Join(updateFolder(o),"pending.json"),raw,0600);err!=nil{t.Fatal(err)}
 if _,_,err:=staged(o);err==nil{t.Fatal("accepted invalid build timestamp in staged update")}
}
