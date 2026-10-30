package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	s.policy = deliveryPolicyState{Greylist: map[string]time.Time{}, Rates: map[string][]time.Time{}}
	data, err := os.ReadFile(filepath.Join(s.dir, "delivery-policy.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &s.policy); err != nil {
		return err
	}
	if s.policy.Greylist == nil {
		s.policy.Greylist = map[string]time.Time{}
	}
	if s.policy.Rates == nil {
		s.policy.Rates = map[string][]time.Time{}
	}
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
	if len(next.Greylist) > 20000 || len(next.Rates) > 20000 {
		return "", "", errors.New("delivery policy state capacity reached; disable policy or investigate hostile traffic")
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
	if err := atomicJSON(filepath.Join(s.dir, "delivery-policy.json"), next); err != nil {
		return "", "", err
	}
	s.policy = next
	return action, reason, nil
}
