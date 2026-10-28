package core

// Optional fingerprint-only HTTPS reputation provider integration. This is an
// intentionally documented JSON API; it is NOT Rspamd's proprietary fuzzy
// wire protocol. No raw email, addresses or URLs are transferred.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type RemoteFuzzyResult struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Samples    int     `json:"samples"`
	Provider   string  `json:"provider"`
}

func CheckRemoteFuzzy(ctx context.Context, raw []byte) (RemoteFuzzyResult, error) {
	target, token := strings.TrimSpace(os.Getenv("SPAMGATE_FUZZY_URL")), os.Getenv("SPAMGATE_FUZZY_TOKEN")
	if target == "" || token == "" {
		return RemoteFuzzyResult{}, errors.New("HTTPS fuzzy provider URL and token must both be configured")
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return RemoteFuzzyResult{}, errors.New("fuzzy provider must use an HTTPS URL without credentials or fragment")
	}
	fingerprint, shingles, err := fuzzyFingerprint(raw)
	if err != nil {
		return RemoteFuzzyResult{}, err
	}
	content, _ := json.Marshal(map[string]any{"algorithm": "spamgate-simhash64-v1", "fingerprint": fmt.Sprintf("%016x", fingerprint), "shingles": shingles})
	deadline, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(deadline, http.MethodPost, target, bytes.NewReader(content))
	if err != nil {
		return RemoteFuzzyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 800 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fuzzy provider redirects forbidden") }}
	resp, err := client.Do(req)
	if err != nil {
		return RemoteFuzzyResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return RemoteFuzzyResult{}, fmt.Errorf("fuzzy provider status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(b) > 4096 {
		return RemoteFuzzyResult{}, errors.New("fuzzy provider response exceeds limit")
	}
	var out RemoteFuzzyResult
	if json.Unmarshal(b, &out) != nil || (out.Label != "spam" && out.Label != "ham" && out.Label != "none") || out.Confidence < 0 || out.Confidence > 1 || out.Samples < 0 || out.Samples > 100000000 {
		return RemoteFuzzyResult{}, errors.New("invalid fuzzy provider response")
	}
	if len(out.Provider) > 80 {
		out.Provider = out.Provider[:80]
	}
	return out, nil
}
