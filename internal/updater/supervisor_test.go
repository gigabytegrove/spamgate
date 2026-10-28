package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stageTestBinary(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	name, e := platformAsset()
	if e != nil {
		t.Skip(e)
	}
	folder := updateDir(dir)
	if e = os.MkdirAll(folder, 0700); e != nil {
		t.Fatal(e)
	}
	binary := []byte(strings.Repeat("updated-executable-", 512))
	sum := sha256.Sum256(binary)
	if e = os.WriteFile(filepath.Join(folder, "pending"+filepath.Ext(name)), binary, 0700); e != nil {
		t.Fatal(e)
	}
	meta, _ := json.Marshal(map[string]string{"Version": "v0.6.0-alpha.11", "Filename": name, "SHA256": hex.EncodeToString(sum[:])})
	if e = os.WriteFile(filepath.Join(folder, "pending.json"), meta, 0600); e != nil {
		t.Fatal(e)
	}
	return "v0.6.0-alpha.11", binary
}
func TestSupervisorDoesNotKillUnsupervisedService(t *testing.T) {
	dir := t.TempDir()
	stageTestBinary(t, dir)
	t.Setenv(SupervisedEnv, "")
	if _, err := ReadyForSupervisorUpdate(dir); err == nil || !strings.Contains(err.Error(), "supervisor") {
		t.Fatalf("expected safe refusal, got %v", err)
	}
	if _, _, err := Pending(dir); err != nil {
		t.Fatalf("safe refusal discarded staged update: %v", err)
	}
}
func TestSupervisorPromotionRollbackAndAudit(t *testing.T) {
	dir := t.TempDir()
	tag, bytes := stageTestBinary(t, dir)
	original := filepath.Join(t.TempDir(), "spamgate-original")
	old := []byte(strings.Repeat("original-executable-", 512))
	if err := os.WriteFile(original, old, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SupervisedEnv, "1")
	if got, err := ReadyForSupervisorUpdate(dir); err != nil || got != tag {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := promoteStaged(dir, original); err != nil || got != tag {
		t.Fatalf("%q %v", got, err)
	}
	active, err := os.ReadFile(runningPath(dir))
	if err != nil || string(active) != string(bytes) {
		t.Fatalf("bad promoted bytes: %v", err)
	}
	if err = Record(dir, "checking", tag, "checking startup"); err != nil {
		t.Fatal(err)
	}
	status, err := LastRecord(dir)
	if err != nil || status.State != "checking" || status.Version != tag {
		t.Fatalf("bad status: %+v %v", status, err)
	}
	if err = rollback(dir); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(runningPath(dir))
	if err != nil || string(restored) != string(old) {
		t.Fatalf("rollback lost original: %v", err)
	}
	if _, _, err = Pending(dir); err != nil {
		t.Fatalf("staged update unexpectedly deleted: %v", err)
	}
	clearPending(dir)
	if _, _, err = Pending(dir); err == nil {
		t.Fatal("pending metadata survived cleanup")
	}
}
func TestHealthProbeIsMeasuredNotAssumed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	idle := make(chan error, 1)
	if err := waitHealthy(context.Background(), server.URL+"/healthz", idle, time.Second); err != nil {
		t.Fatal(err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer bad.Close()
	if err := waitHealthy(context.Background(), bad.URL+"/healthz", idle, 350*time.Millisecond); err == nil {
		t.Fatal("5xx incorrectly counted as healthy")
	}
}
func TestReadyURLForWildcardAndCustomPort(t *testing.T) {
	t.Setenv("SPAMGATE_WEB_LISTEN", "0.0.0.0:38470")
	if x := readyURL([]string{"-data", "/tmp/sg", "-listen", "0.0.0.0:39001"}); x != "http://127.0.0.1:39001/healthz" {
		t.Fatal(x)
	}
}
