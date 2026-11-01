package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"v0.6.0-alpha.6", "0.6.0-alpha.5", 1}, {"v0.6.0", "v0.6.0-rc.8", 1}, {"v0.5.0", "0.6.0-alpha.2", -1}, {"0.6.0-alpha.9", "0.6.0-alpha.10", -1}, {"v0.6.0-beta.1", "v0.6.0-alpha.12", 1}}
	for _, c := range cases {
		v, e := compare(c.a, c.b)
		if e != nil || v != c.want {
			t.Fatalf("%s vs %s = %d %v", c.a, c.b, v, e)
		}
	}
}
func TestIndependentHourlyBuildReleaseOrder(t *testing.T) {
 cases := []struct{ a,b string;want int }{
  {"v0.6.0-beta.2+20261101-01","0.6.0-beta.2",1},
  {"v0.6.0-beta.2+20261101-01a","v0.6.0-beta.2+20261101-01",1},
  {"v0.6.0-beta.2+20261101-01z","v0.6.0-beta.2+20261101-02",-1},
  {"v0.6.0-beta.3","v0.6.0-beta.2+20261101-23z",1},
  {"v0.6.0-beta.2+20261101-02","v0.6.0-beta.2+20261101-02",0},
 }
 for _,tc :=range cases {
  got,err:=compare(tc.a,tc.b)
  if err!=nil||got!=tc.want{t.Errorf("compare(%q,%q)=%d %v; want %d",tc.a,tc.b,got,err,tc.want)}
 }
 for _,tag:=range []string{"v0.6.0-beta.2+20261101-24","v0.6.0-beta.2+20260230-01","v0.6.0-beta.2+20261101-01A"} {
  if _,err:=compare(tag,"v0.6.0-beta.2");err==nil{t.Errorf("accepted invalid build tag %q",tag)}
 }
}

func TestLatestIncludesPrereleases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"tag_name":"v0.6.0-alpha.6"},{"tag_name":"v0.5.0"},{"tag_name":"v9.0.0","draft":true}]`)
	}))
	defer server.Close()
	c := New()
	c.Endpoint = server.URL // fixture calls are restricted to the explicitly configured endpoint.
	r, e := c.Latest(context.Background())
	if e != nil || r.Tag != "v0.6.0-alpha.6" {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestStagedFileTampering(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("unsupported architecture")
	}
	dir := t.TempDir()
	name, e := platformAsset()
	if e != nil {
		t.Skip(e)
	}
	folder := filepath.Join(dir, "updates")
	if e = os.MkdirAll(folder, 0700); e != nil {
		t.Fatal(e)
	}
	binary := []byte(strings.Repeat("binary", 1024))
	h := sha256.Sum256(binary)
	digest := hex.EncodeToString(h[:])
	if e = os.WriteFile(filepath.Join(folder, "pending"+filepath.Ext(name)), binary, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(folder, "pending.json"), []byte(fmt.Sprintf(`{"Version":"v0.6.0-alpha.6","Filename":%q,"SHA256":%q}`, name, digest)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Pending(dir); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(folder, "pending"+filepath.Ext(name)), []byte("tampered"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Pending(dir); e == nil {
		t.Fatal("tampered bytes accepted")
	}
}
func TestUntrustedAssetsRejected(t *testing.T) {
	r := Release{Tag: "v0.6.0-alpha.6", Assets: []Asset{{Name: "spamgate-linux-amd64", Size: 10000, URL: "https://malicious.example/binary"}}}
	if _, e := lookup(r, "spamgate-linux-amd64"); e == nil {
		t.Fatal("untrusted asset accepted")
	}
}

// Legacy native/systemd/Docker supervisors must continue downloading a worker.
// Only the new split launcher can select the split worker release asset.
func TestSplitWorkerAssetSelection(t *testing.T) {
 if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" { t.Skip("Linux AMD64 selection") }
 t.Setenv("SPAMGATE_SPLIT_WORKER", "")
 legacy, err := platformAsset()
 if err != nil || legacy != "spamgate-linux-amd64" { t.Fatalf("legacy: %q %v",legacy,err) }
 t.Setenv("SPAMGATE_SPLIT_WORKER", "1")
 split, err := platformAsset()
 if err != nil || split != "spamgate-worker-linux-amd64" { t.Fatalf("new split layout: %q %v",split,err) }
}
