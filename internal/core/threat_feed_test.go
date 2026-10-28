package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThreatFeedSnapshotFreshnessAndAttribution(t *testing.T) {
	write := func(dir string, feed ThreatFeed) string {
		t.Helper()
		path := filepath.Join(dir, "threat-feed.json")
		b, _ := json.Marshal(feed)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	now := time.Now().UTC()
	f := ThreatFeed{Source: "Curated fixture", GeneratedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), IPs: []string{"8.8.8.8"}, Domains: []string{"bad.example"}}
	path := write(t.TempDir(), f)
	t.Setenv("SPAMGATE_THREAT_FEED_FILE", path)
	found, e := FindThreatFeedMatches("8.8.8.8", []string{"mail.bad.example", "notbad.example"})
	if e != nil {
		t.Fatal(e)
	}
	if len(found) != 2 || found[0].Symbol != "THREAT_FEED_IP" || found[1].Symbol != "THREAT_FEED_DOMAIN" || !strings.Contains(found[1].Detail, "Curated fixture") {
		t.Fatalf("bad indicator matching: %+v", found)
	}
	if fnd, e := FindThreatFeedMatches("1.1.1.1", []string{"good.example", "notbad.example"}); e != nil || len(fnd) != 0 {
		t.Fatalf("false positive from domain suffix: %+v %v", fnd, e)
	}
	f.ExpiresAt = now.Add(-time.Second)
	expiredPath := write(t.TempDir(), f)
	t.Setenv("SPAMGATE_THREAT_FEED_FILE", expiredPath)
	if _, e = FindThreatFeedMatches("8.8.8.8", nil); e == nil {
		t.Fatal("expired feed was used")
	}
	f.ExpiresAt = now.Add(time.Hour)
	f.Domains = []string{"co.uk"}
	publicSuffixPath := write(t.TempDir(), f)
	t.Setenv("SPAMGATE_THREAT_FEED_FILE", publicSuffixPath)
	if _, e = FindThreatFeedMatches("8.8.8.8", nil); e == nil {
		t.Fatal("public suffix as feed indicator accepted")
	}
	f.Domains = []string{"bad.example\nX-injected: value"}
	invalidPath := write(t.TempDir(), f)
	t.Setenv("SPAMGATE_THREAT_FEED_FILE", invalidPath)
	if _, e = FindThreatFeedMatches("8.8.8.8", nil); e == nil {
		t.Fatal("malformed feed was accepted")
	}
}
