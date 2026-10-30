package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type updateFixtureTransport map[string][]byte

func (f updateFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, ok := f[req.URL.String()]
	if !ok {
		return nil, fmt.Errorf("unexpected update request: %s", req.URL)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status: "200 OK",
		Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Header: make(http.Header),
		Request: req,
	}, nil
}

func stagingFixtureClient(t *testing.T) *Client {
	t.Helper()
	name, err := platformAsset()
	if err != nil {
		t.Skip(err)
	}
	binary := bytes.Repeat([]byte("S"), 8192)
	if runtime.GOOS == "windows" {
		copy(binary, "MZ")
	} else {
		copy(binary, "\x7fELF")
	}
	sum := sha256.Sum256(binary)
	digest := hex.EncodeToString(sum[:])
	tag := "v0.6.0-beta.9"
	prefix := "https://github.com/gigabytegrove/spamgate/releases/download/" + tag + "/"
	checks := []byte(fmt.Sprintf("%s  %s\n", digest, name))
	release := Release{
		Tag: tag,
		HTML: "https://github.com/gigabytegrove/spamgate/releases/tag/" + tag,
		Assets: []Asset{
			{Name: name, Size: int64(len(binary)), URL: prefix + name},
			{Name: "SHA256SUMS.txt", Size: int64(len(checks)), URL: prefix + "SHA256SUMS.txt"},
		},
	}
	metadata, err := json.Marshal([]Release{release})
	if err != nil {
		t.Fatal(err)
	}
	client := New()
	client.HTTP = &http.Client{Transport: updateFixtureTransport{
		client.Endpoint: metadata,
		prefix + name: binary,
		prefix + "SHA256SUMS.txt": checks,
	}}
	return client
}

func TestStageReplacesSymlinkedMetadataWithoutTouchingConfig(t *testing.T) {
	dir := t.TempDir()
	updates := filepath.Join(dir, "updates")
	if err := os.Mkdir(updates, 0700); err != nil { t.Fatal(err) }
	victim := filepath.Join(dir, "config.json")
	if err := os.WriteFile(victim, []byte("persistent settings"), 0600); err != nil { t.Fatal(err) }
	metadata := filepath.Join(updates, "pending.json")
	if err := os.Symlink(victim, metadata); err != nil { t.Skip(err) }

	client := stagingFixtureClient(t)
	status, err := client.Stage(context.Background(), "v0.6.0-beta.1", dir)
	if err != nil || !status.Staged {
		t.Fatalf("verified release failed staging: %+v %v", status, err)
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "persistent settings" {
		t.Fatalf("staging overwrote persistent config: %q %v", got, err)
	}
	info, err := os.Lstat(metadata)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("pending metadata is not a regular file: %v %v", info, err)
	}
	_, version, err := Pending(dir)
	if err != nil || version != "v0.6.0-beta.9" {
		t.Fatalf("newly staged binary not independently verified: %q %v", version, err)
	}
	entries, err := os.ReadDir(updates)
	if err != nil { t.Fatal(err) }
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".spamgate-update-") {
			t.Fatalf("temporary staging file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestStageRefusesSymlinkedUpdateDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "updates")); err != nil { t.Skip(err) }
	client := stagingFixtureClient(t)
	if _, err := client.Stage(context.Background(), "v0.6.0-beta.1", dir); err == nil {
		t.Fatal("staged a release through a symlinked updates directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlinked destination was modified: %v %v", entries, err)
	}
}
