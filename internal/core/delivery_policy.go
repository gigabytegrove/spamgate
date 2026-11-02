package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// deliveryPolicyState is local, bounded and persisted. No sender addresses or
// recipient addresses are stored: triplets and source IPs are SHA-256 hashed.
// This is a single-host implementation, not distributed shared reputation.
type deliveryPolicyState struct {
	Greylist map[string]time.Time   `json:"greylist"`
	Rates    map[string][]time.Time `json:"rates"`
}

func (s *Store) loadDeliveryPolicy() error {
	next, err := readDeliveryPolicyState(filepath.Join(s.dir, "delivery-policy.json"))
	if errors.Is(err, os.ErrNotExist) {
		s.policy = deliveryPolicyState{Greylist: map[string]time.Time{}, Rates: map[string][]time.Time{}}
		s.policyFileSeen = false
		return nil
	}
	if err != nil {
		return err
	}
	s.policy = next
	s.policyFileSeen = true
	return nil
}
func stablePolicyKey(elements ...string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.Join(elements, "\x00"))))
	return hex.EncodeToString(h[:])
}
func policyIP(source string) string {
	ip := net.ParseIP(source)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ""
	}
	return ip.String()
}
func (s *Store) EvaluateDeliveryPolicy(m Message, now time.Time) (string, string, error) {
	cfg := s.Config().Settings
	if !cfg.GreylistEnabled && !cfg.RateLimitEnabled {
		return "", "", nil
	}
	ip := policyIP(m.ClientIP)
	if m.Connector != "milter" || ip == "" {
		return "", "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Multiple native workers may share /opt/spamgate/data. Serialize the
	// read/modify/write cycle across processes and refresh counters under
	// the same inode-stable lock before making an SMTP disposition.
	unlock, err := acquireDeliveryPolicyLock(s.dir)
	if err != nil {
		return "", "", fmt.Errorf("lock delivery policy: %w", err)
	}
	defer unlock()
	path := filepath.Join(s.dir, "delivery-policy.json")
	persisted, err := readDeliveryPolicyState(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if s.policyFileSeen {
			return "", "", errors.New("delivery policy state disappeared; refusing to reset enforcement counters")
		}
	case err != nil:
		return "", "", fmt.Errorf("reload delivery policy state: %w", err)
	default:
		s.policy = persisted
		s.policyFileSeen = true
	}
	// Compute the entire next state without mutating the live state. A failed
	// fsync/rename must not silently consume a rate allowance or expire a
	// greylist entry in memory while the on-disk policy remains unchanged.
	next := deliveryPolicyState{
		Greylist: make(map[string]time.Time, len(s.policy.Greylist)),
		Rates:    make(map[string][]time.Time, len(s.policy.Rates)),
	}
	for k, first := range s.policy.Greylist {
		if now.Sub(first) <= 36*time.Hour && !first.After(now.Add(time.Minute)) {
			next.Greylist[k] = first
		}
	}
	for k, stamps := range s.policy.Rates {
		live := make([]time.Time, 0, len(stamps))
		for _, ts := range stamps {
			if !ts.After(now) && now.Sub(ts) < time.Hour {
				live = append(live, ts)
			}
		}
		if len(live) != 0 {
			next.Rates[k] = live
		}
	}
	
	action, reason := "", ""
	if cfg.RateLimitEnabled {
		limit := cfg.RateLimitPerHour
		if limit == 0 {
			limit = 240
		}
		k := stablePolicyKey("rate", ip)
		if len(next.Rates[k]) >= limit {
			action = "soft_reject"
			reason = "Source IP exceeded the configured messages/hour allowance"
		} else {
			next.Rates[k] = append(next.Rates[k], now)
		}
	}
	if action == "" && cfg.GreylistEnabled && m.Action == "tag" {
		delay := cfg.GreylistWaitMinutes
		if delay == 0 {
			delay = 5
		}
		recipients := append([]string(nil), m.Recipients...)
		sort.Strings(recipients)
		sender := strings.ToLower(strings.TrimSpace(m.Sender))
		k := stablePolicyKey("greylist", ip, sender, strings.Join(recipients, ","))
		first, seen := next.Greylist[k]
		if !seen {
			next.Greylist[k] = now
			action = "soft_reject"
			reason = "First suspicious message from this IP/sender/recipient combination; retry after greylist delay"
		} else if now.Sub(first) < time.Duration(delay)*time.Minute {
			action = "soft_reject"
			reason = "Sender retried before greylist delay elapsed"
		}
	}
	if err := validateDeliveryPolicyState(next); err != nil {
		return "", "", err
	}
	if err := atomicJSON(path, next); err != nil {
		return "", "", err
	}
	// Rename has published the file. Mark it as known even if the parent
	// directory fsync fails, so a later disappearance cannot reset counters.
	s.policyFileSeen = true
	if err := syncAtomicParent(path); err != nil {
		return "", "", fmt.Errorf("sync delivery policy directory: %w", err)
	}
	s.policy = next
	return action, reason, nil
}
