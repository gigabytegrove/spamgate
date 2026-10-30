package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const Endpoint = "https://api.github.com/repos/gigabytegrove/spamgate/releases?per_page=30"
const maxBinary = 80 << 20

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+)?$`)
var hexDigest = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}
type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
	HTML       string  `json:"html_url"`
}
type Status struct {
	Current     string        `json:"current"`
	Latest      string        `json:"latest,omitempty"`
	Available   bool          `json:"available"`
	ReleaseURL  string        `json:"release_url,omitempty"`
	Staged      bool          `json:"staged"`
	Message     string        `json:"message,omitempty"`
	InstallMode string        `json:"install_mode,omitempty"`
	InstallPath string        `json:"install_path,omitempty"`
	LastUpdate  *UpdateRecord `json:"last_update,omitempty"`
}
type Client struct {
	HTTP     *http.Client
	Endpoint string
}

func New() *Client { return &Client{HTTP: &http.Client{Timeout: 35 * time.Second}, Endpoint: Endpoint} }
func platformAsset() (string, error) {
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("updates are unavailable on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	switch runtime.GOOS {
	case "linux":
		// The old native and managed Linux supervisors still install the
		// legacy worker asset. The independent native launcher explicitly
		// marks its child, which uses the dedicated worker asset instead.
		if os.Getenv("SPAMGATE_SPLIT_WORKER") == "1" {
			return "spamgate-worker-linux-amd64", nil
		}
		return "spamgate-linux-amd64", nil
	case "windows":
		return "spamgate-windows-amd64.exe", nil
	}
	return "", errors.New("unsupported platform")
}
func compare(a, b string) (int, error) {
	parse := func(s string) ([]int, error) {
		s = strings.TrimPrefix(s, "v")
		x := strings.SplitN(s, "-", 2)
		p := strings.Split(x[0], ".")
		if len(p) != 3 {
			return nil, errors.New("invalid version")
		}
		out := make([]int, 5)
		for i := 0; i < 3; i++ {
			n, e := strconv.Atoi(p[i])
			if e != nil {
				return nil, e
			}
			out[i] = n
		}
		out[3] = 4
		if len(x) > 1 {
			z := strings.Split(x[1], ".")
			if len(z) != 2 {
				return nil, errors.New("invalid prerelease")
			}
			ranks := map[string]int{"alpha": 1, "beta": 2, "rc": 3}
			out[3] = ranks[z[0]]
			if out[3] == 0 {
				return nil, errors.New("unknown prerelease")
			}
			n, e := strconv.Atoi(z[1])
			if e != nil {
				return nil, e
			}
			out[4] = n
		}
		return out, nil
	}
	aa, e := parse(a)
	if e != nil {
		return 0, e
	}
	bb, e := parse(b)
	if e != nil {
		return 0, e
	}
	for i := range aa {
		if aa[i] > bb[i] {
			return 1, nil
		}
		if aa[i] < bb[i] {
			return -1, nil
		}
	}
	return 0, nil
}
func (c *Client) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://github.com/gigabytegrove/spamgate/releases/download/") && url != c.Endpoint {
		return nil, errors.New("untrusted update origin")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "SpamGate-Updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, e := c.HTTP.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("update service returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, errors.New("download too large")
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > limit {
		return nil, errors.New("download too large")
	}
	return data, nil
}
func (c *Client) Latest(ctx context.Context) (Release, error) {
	b, err := c.get(ctx, c.Endpoint, 1<<20)
	if err != nil {
		return Release{}, err
	}
	var releases []Release
	if err = json.Unmarshal(b, &releases); err != nil {
		return Release{}, err
	}
	var latest Release
	for _, r := range releases {
		if r.Draft || !releaseTag.MatchString(r.Tag) {
			continue
		}
		if latest.Tag == "" {
			latest = r
			continue
		}
		cmp, e := compare(r.Tag, latest.Tag)
		if e == nil && cmp > 0 {
			latest = r
		}
	}
	if latest.Tag == "" {
		return Release{}, errors.New("no valid published GitHub release found")
	}
	return latest, nil
}
func lookup(r Release, name string) (Asset, error) {
	var found Asset
	count := 0
	for _, a := range r.Assets {
		if a.Name == name {
			found = a
			count++
		}
	}
	if count != 1 || found.Size < 1 || found.Size > maxBinary {
		return Asset{}, fmt.Errorf("release requires one valid %s asset", name)
	}
	expected := "https://github.com/gigabytegrove/spamgate/releases/download/" + r.Tag + "/" + name
	if found.URL != expected {
		return Asset{}, errors.New("release asset URL does not match expected GitHub location")
	}
	return found, nil
}
func (c *Client) Check(ctx context.Context, current string) (Status, error) {
	s := Status{Current: current}
	r, e := c.Latest(ctx)
	if e != nil {
		return s, e
	}
	comparison, e := compare(r.Tag, current)
	if e != nil {
		return s, e
	}
	s.Latest = r.Tag
	s.Available = comparison > 0
	s.ReleaseURL = r.HTML
	name, e := platformAsset()
	if e != nil {
		return s, e
	}
	if s.Available {
		if _, e = lookup(r, name); e != nil {
			return s, e
		}
		if _, e = lookup(r, "SHA256SUMS.txt"); e != nil {
			return s, e
		}
	}
	return s, nil
}
func (c *Client) Stage(ctx context.Context, current, dir string) (Status, error) {
	s, rerr := c.Check(ctx, current)
	if rerr != nil || !s.Available {
		return s, rerr
	}
	r, e := c.Latest(ctx)
	if e != nil {
		return s, e
	}
	if r.Tag != s.Latest {
		return s, errors.New("release changed during update check")
	}
	name, _ := platformAsset()
	a, e := lookup(r, name)
	if e != nil {
		return s, e
	}
	checks, e := lookup(r, "SHA256SUMS.txt")
	if e != nil {
		return s, e
	}
	raw, e := c.get(ctx, checks.URL, 1<<20)
	if e != nil {
		return s, e
	}
	var expected string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name && hexDigest.MatchString(fields[0]) {
			if expected != "" {
				return s, errors.New("duplicate checksum")
			}
			expected = strings.ToLower(fields[0])
		}
	}
	if expected == "" {
		return s, errors.New("release checksum missing")
	}
	binary, e := c.get(ctx, a.URL, maxBinary)
	if e != nil {
		return s, e
	}
	if int64(len(binary)) != a.Size {
		return s, errors.New("binary length mismatch")
	}
	hash := sha256.Sum256(binary)
	if hex.EncodeToString(hash[:]) != expected {
		return s, errors.New("binary SHA-256 mismatch")
	}
	if len(binary) < 4096 {
		return s, errors.New("invalid binary length")
	}
	if runtime.GOOS == "windows" && !strings.HasPrefix(string(binary[:2]), "MZ") {
		return s, errors.New("not a Windows executable")
	}
	if runtime.GOOS == "linux" && string(binary[:4]) != "\x7fELF" {
		return s, errors.New("not a Linux executable")
	}
	destination := filepath.Join(dir, "updates")
	if e = ensureUpdateDir(destination, true); e != nil {
		return s, e
	}
	if e = atomicUpdateFile(destination, "pending"+filepath.Ext(name), binary, 0700); e != nil {
		return s, e
	}
	record := struct{ Version, Filename, SHA256 string }{r.Tag, name, expected}
	b, e := json.Marshal(record)
	if e != nil {
		return s, e
	}
	if e = atomicUpdateFile(destination, "pending.json", b, 0600); e != nil {
		return s, e
	}
	s.Staged = true
	return s, nil
}

// Pending independently verifies the staged bytes before any executable replacement.
// pendingDetails binds the verified digest to the later executable copy.
func pendingDetails(dir string) (string, string, string, error) {
	base := filepath.Join(dir, "updates")
	if err := ensureUpdateDir(base, false); err != nil {
		return "", "", "", err
	}
	raw, err := readUpdateRegularFile(filepath.Join(base, "pending.json"), 4096)
	if err != nil {
		return "", "", "", err
	}
	var m struct{ Version, Filename, SHA256 string }
	if err = json.Unmarshal(raw, &m); err != nil {
		return "", "", "", err
	}
	expected, _ := platformAsset()
	if m.Filename != expected || !releaseTag.MatchString(m.Version) || !hexDigest.MatchString(m.SHA256) {
		return "", "", "", errors.New("invalid staged update metadata")
	}
	path := filepath.Join(base, "pending"+filepath.Ext(expected))
	f, info, err := openUpdateRegularFile(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()
	if info.Size() > maxBinary || info.Size() < 4096 {
		return "", "", "", errors.New("invalid staged binary")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", "", "", err
	}
	after, err := f.Stat()
	if err != nil {
		return "", "", "", err
	}
	if !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return "", "", "", errors.New("staged binary changed during verification")
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(m.SHA256) {
		return "", "", "", errors.New("staged update checksum changed")
	}
	return path, m.Version, strings.ToLower(m.SHA256), nil
}

// Pending preserves the public three-value interface for existing callers.
func Pending(dir string) (string, string, error) {
 path, version, _, err := pendingDetails(dir)
 return path, version, err
}
