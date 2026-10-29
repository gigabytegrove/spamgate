package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArgumentsPreserved(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "spamgate-worker")
	if err := os.WriteFile(binary, []byte("valid"), 0700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	opts, err := parse([]string{"-worker", binary, "-data", data, "-listen", "0.0.0.0:38470", "-log-level", "debug"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.worker != binary || opts.data != data || len(opts.args) != 6 {
		t.Fatalf("options: %+v", opts)
	}
	if opts.listen != "0.0.0.0:38470" {
		t.Fatal(opts.listen)
	}
}

func TestRejectTamperedPayloadAndSymlink(t *testing.T) {
	dir := t.TempDir()
	o := options{data: dir, worker: filepath.Join(dir, "spamgate-worker")}
	if err := os.MkdirAll(updateFolder(o), 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(strings.Repeat("TEST", 1500))
	h := sha256.Sum256(raw)
	m := updateManifest{Version: "v0.6.0-alpha.13", Filename: "spamgate-worker-linux-amd64", SHA256: hex.EncodeToString(h[:])}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(updateFolder(o), "pending.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(updateFolder(o), "pending")
	if err := os.WriteFile(target, raw, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := staged(o); err != nil {
		t.Fatal(err)
	}
	raw[6] = 'Z'
	if err := os.WriteFile(target, raw, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := staged(o); err == nil {
		t.Fatal("tampered pending binary accepted")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(o.worker, target); err != nil {
		t.Fatal(err)
	}
	if _, _, err := staged(o); err == nil {
		t.Fatal("symlink staged executable accepted")
	}
}

const fixture = `package main
import("fmt";"os";"net/http";"os/signal";"syscall")
const version=%q
const broken=%t
func main(){
 if len(os.Args)==2 && os.Args[1]=="-version" {fmt.Println(version);return}
 if broken {os.Exit(3)}
 listen:="127.0.0.1:38470"
 for i:=1;i<len(os.Args);i++ {if os.Args[i]=="-listen" && i+1<len(os.Args) {listen=os.Args[i+1];i++}}
 mux:=http.NewServeMux()
 mux.HandleFunc("/healthz",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");fmt.Fprintf(w,"{\"version\":%%q}",version)})
 mux.HandleFunc("/trigger",func(w http.ResponseWriter,r *http.Request){w.WriteHeader(202);w.(http.Flusher).Flush();go func(){os.Exit(75)}()})
 s:=&http.Server{Addr:listen,Handler:mux}
 signalChan:=make(chan os.Signal,1);signal.Notify(signalChan,os.Interrupt,syscall.SIGTERM)
 go func(){<-signalChan;_ =s.Close();os.Exit(0)}()
 if err:=s.ListenAndServe();err!=nil&&err!=http.ErrServerClosed{os.Exit(4)}
}`

func buildFixture(t *testing.T, dir, name, ver string, broken bool) string {
	t.Helper()
	root := filepath.Join(dir, "src-"+name)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(fixture, ver, broken)
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", target, "main.go")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build fixture %s: %v: %s", name, err, out)
	}
	return target
}

func port(t *testing.T) string {
	t.Helper()
	s, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return s.Addr().String()
}
func awaitVersion(t *testing.T, address, version string) {
	t.Helper()
	deadline := time.Now().Add(13 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + address + "/healthz")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
			resp.Body.Close()
			var result struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(body, &result)
			if result.Version == version {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("failed to observe healthy worker version %s", version)
}
func installFixture(t *testing.T, o options, source, version string) {
	t.Helper()
	folder := updateFolder(o)
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	if err := os.WriteFile(filepath.Join(folder, "pending"), b, 0700); err != nil {
		t.Fatal(err)
	}
	m := updateManifest{Version: "v" + version, Filename: "spamgate-worker-linux-amd64", SHA256: hex.EncodeToString(h[:])}
	j, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(folder, "pending.json"), j, 0600); err != nil {
		t.Fatal(err)
	}
}
func awaitStatus(t *testing.T, o options, expected string) {
	t.Helper()
	deadline := time.Now().Add(13 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(updateFolder(o), "last-update.json"))
		if err == nil {
			var state updateRecord
			if json.Unmarshal(b, &state) == nil && state.State == expected {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("missing state %s", expected)
}
func TestRunnerEndToEndUpgradeAndRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("integration build")
	}
	for _, broken := range []bool{false, true} {
		title := "healthy"
		if broken {
			title = "rollback"
		}
		t.Run(title, func(t *testing.T) {
			dir := t.TempDir()
			original := buildFixture(t, dir, "original", "0.6.0-alpha.11", false)
			updated := buildFixture(t, dir, "candidate", "0.6.0-alpha.12", broken)
			installed := filepath.Join(dir, "spamgate-worker")
			if err := copyAtomic(original, installed); err != nil {
				t.Fatal(err)
			}
			o := options{worker: installed, data: filepath.Join(dir, "data"), listen: port(t), args: []string{"-data", filepath.Join(dir, "data"), "-listen", ""}}
			o.args[3] = o.listen
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- supervise(ctx, o) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("supervisor: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("supervisor did not exit")
				}
			}()
			awaitVersion(t, o.listen, "0.6.0-alpha.11")
			time.Sleep(700 * time.Millisecond) // allow runner to finish its initial readiness check
			installFixture(t, o, updated, "0.6.0-alpha.12")
			response, err := http.Get("http://" + o.listen + "/trigger")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			want := "0.6.0-alpha.12"
			status := "healthy"
			if broken {
				want = "0.6.0-alpha.11"
				status = "rolled_back"
			}
			awaitStatus(t, o, status)
			awaitVersion(t, o.listen, want)
			actual, err := executableVersion(o.worker)
			if err != nil || actual != want {
				t.Fatalf("installed worker path mismatch: got %s, error %v", actual, err)
			}
			if _, err := os.Stat(o.worker + ".spamgate-backup"); !os.IsNotExist(err) {
				t.Fatalf("legacy backup was modified: %v", err)
			}
		})
	}
}

func TestVersionMonotonic(t *testing.T) {
	for _, x := range []struct {
		a, b string
		want int
	}{
		{"0.6.0-alpha.12", "0.6.0-alpha.11", 1},
		{"0.6.0-alpha.11", "0.6.0-alpha.12", -1},
		{"0.6.0-alpha.12", "0.6.0-alpha.12", 0},
		{"0.6.0-beta.1", "0.6.0-alpha.20", 1},
		{"1.0.0", "1.0.0-rc.3", 1},
	} {
		got, err := compareVersions(x.a, x.b)
		if err != nil || got != x.want {
			t.Fatalf("compare %s/%s got=%d err=%v", x.a, x.b, got, err)
		}
	}
}
