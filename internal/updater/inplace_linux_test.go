//go:build linux

package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executableFixture(t *testing.T, path, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { t.Fatal(err) }
	script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo "+version+"; fi\n#"+strings.Repeat("x", 5000)+"\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil { t.Fatal(err) }
}

func TestInPlaceExecutableMigratesLatestOverlayAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(InPlaceEnv, "1")
	base := filepath.Join(t.TempDir(),"spamgate-base")
	executableFixture(t, base,"0.6.0-alpha.11")
	executableFixture(t, runningPath(dir),"0.6.0-alpha.12")
	if err := seedInPlaceBinary(dir, base); err != nil { t.Fatal(err) }
	installed := ActiveBinaryPath(dir)
	if installed != filepath.Join(dir,"bin","spamgate") { t.Fatal(installed) }
	if got,err := executableVersion(installed); err != nil || got != "0.6.0-alpha.12" { t.Fatalf("did not migrate newest version: %q %v",got,err) }
	name,err := platformAsset(); if err != nil { t.Fatal(err) }
	pending := filepath.Join(updateDir(dir),"pending")
	executableFixture(t,pending,"0.6.0-alpha.13")
	contents,err:=os.ReadFile(pending);if err != nil { t.Fatal(err) }
	sum:=sha256.Sum256(contents)
	meta,_:=json.Marshal(map[string]string{"Version":"v0.6.0-alpha.13","Filename":name,"SHA256":hex.EncodeToString(sum[:])})
	if err:=os.WriteFile(filepath.Join(updateDir(dir),"pending.json"),meta,0600);err!=nil{t.Fatal(err)}
	version,err:=promoteStaged(dir,base);if err!=nil || version!="v0.6.0-alpha.13"{t.Fatalf("promote: %v %s",err,version)}
	if got,_:=executableVersion(installed);got!="0.6.0-alpha.13"{t.Fatalf("installed binary not promoted: %s",got)}
	if err:=rollback(dir);err!=nil{t.Fatal(err)}
	if got,_:=executableVersion(installed);got!="0.6.0-alpha.12"{t.Fatalf("installed binary not rolled back: %s",got)}
	if got,_:=executableVersion(base);got!="0.6.0-alpha.11"{t.Fatalf("protected fallback was modified: %s",got)}
	// An already installed newer executable must not be overwritten by a stale base or legacy overlay.
	if err:=seedInPlaceBinary(dir,base);err!=nil{t.Fatal(err)}
	if got,_:=executableVersion(installed);got!="0.6.0-alpha.12"{t.Fatalf("seed downgraded installed version: %s",got)}
}

func TestInPlaceRejectsSymlinkAndLegacyModeUnchanged(t *testing.T) {
	dir:=t.TempDir()
	base:=filepath.Join(t.TempDir(),"spamgate-base")
	executableFixture(t,base,"0.6.0-alpha.11")
	t.Setenv(InPlaceEnv,"1")
	outside:=filepath.Join(t.TempDir(),"outside")
	executableFixture(t,outside,"0.6.0-alpha.99")
	if err:=os.MkdirAll(filepath.Join(dir,"bin"),0700);err!=nil{t.Fatal(err)}
	if err:=os.Symlink(outside,ActiveBinaryPath(dir));err!=nil{t.Fatal(err)}
	if err:=seedInPlaceBinary(dir,base);err==nil || !strings.Contains(err.Error(),"non-regular"){t.Fatalf("expected unsafe symlink refusal, got %v",err)}
	t.Setenv(InPlaceEnv,"")
	if ActiveBinaryPath(dir)!=runningPath(dir){t.Fatal("legacy updater path changed")}
}
