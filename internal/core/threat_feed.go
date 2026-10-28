package core

// Optional locally managed threat-intelligence snapshot. A trusted updater or
// administrator installs a JSON file atomically. SpamGate never downloads
// arbitrary URLs from an email or trusts a stale feed as current intelligence.
import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ThreatFeed struct {
	Source      string    `json:"source"`
	GeneratedAt time.Time `json:"generated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Domains     []string  `json:"domains"`
	IPs         []string  `json:"ips"`
}
type ThreatFeedMatch struct{ Symbol, Detail string }

var feedCache struct {
	sync.Mutex
	path    string
	checked time.Time
	feed    ThreatFeed
	err     error
}

func loadThreatFeed(path string) (ThreatFeed, error) {
	var out ThreatFeed
	st, err := os.Lstat(path)
	if err != nil {
		return out, err
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return out, errors.New("threat feed must be a regular file no larger than 2 MiB")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(content, &out); err != nil {
		return out, fmt.Errorf("invalid threat feed JSON: %w", err)
	}
	now := time.Now().UTC()
	if out.Source == "" || len(out.Source) > 80 || strings.ContainsAny(out.Source, "\r\n") || out.GeneratedAt.IsZero() || out.ExpiresAt.IsZero() || out.GeneratedAt.After(now.Add(10*time.Minute)) || !out.ExpiresAt.After(now) || out.ExpiresAt.Sub(out.GeneratedAt) > 7*24*time.Hour || len(out.Domains) > 10000 || len(out.IPs) > 10000 {
		return ThreatFeed{}, errors.New("invalid source, feed freshness or entry limits")
	}
	for _, domain := range out.Domains {
		if !ValidReputationDomain(domain) || domain != strings.ToLower(domain) || organizationalDomain(domain) == "" {
			return ThreatFeed{}, fmt.Errorf("invalid or non-normalized domain in threat feed")
		}
	}
	for _, ip := range out.IPs {
		parsed := net.ParseIP(ip)
		if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
			return ThreatFeed{}, errors.New("invalid or private feed IP")
		}
	}
	return out, nil
}
func FindThreatFeedMatches(clientIP string, domains []string) ([]ThreatFeedMatch, error) {
	path := os.Getenv("SPAMGATE_THREAT_FEED_FILE")
	if path == "" {
		return nil, errors.New("SPAMGATE_THREAT_FEED_FILE is not configured")
	}
	feedCache.Lock()
	now := time.Now()
	// Recheck every 30 seconds, including expiration and file replacement.
	if feedCache.path != path || now.Sub(feedCache.checked) >= 30*time.Second {
		feedCache.feed, feedCache.err = loadThreatFeed(path)
		feedCache.path = path
		feedCache.checked = now
	}
	feed, err := feedCache.feed, feedCache.err
	feedCache.Unlock()
	if err != nil {
		return nil, err
	}
	if !feed.ExpiresAt.After(now) {
		return nil, errors.New("threat feed expired")
	}
	matches := []ThreatFeedMatch{}
	ip := net.ParseIP(clientIP)
	if ip != nil {
		for _, blocked := range feed.IPs {
			if ip.Equal(net.ParseIP(blocked)) {
				matches = append(matches, ThreatFeedMatch{"THREAT_FEED_IP", fmt.Sprintf("Source %s: listed IP %s (snapshot %s)", feed.Source, blocked, feed.GeneratedAt.Format(time.RFC3339))})
				break
			}
		}
	}
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if !ValidReputationDomain(d) || seen[d] {
			continue
		}
		seen[d] = true
		for _, bad := range feed.Domains {
			if d == bad || strings.HasSuffix(d, "."+bad) {
				matches = append(matches, ThreatFeedMatch{"THREAT_FEED_DOMAIN", fmt.Sprintf("Source %s: %s matched %s (snapshot %s)", feed.Source, d, bad, feed.GeneratedAt.Format(time.RFC3339))})
				break
			}
		}
		if len(matches) >= 5 {
			break
		}
	}
	return matches, nil
}
