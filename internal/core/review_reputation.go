package core

import (
	"strings"
)

type ReviewedDomainReputation struct {
	Domain        string  `json:"domain"`
	ConfirmedSpam int     `json:"confirmed_spam"`
	ConfirmedHam  int     `json:"confirmed_ham"`
	Ready         bool    `json:"ready"`
	Weight        float64 `json:"weight"`
}

// A human review affects *authenticated* future mail only, never creates an
// unconditional allow/reject. Contributions require four independent reviewed
// message IDs whose original scan passed DMARC for the same From domain.
func (s *Store) ReviewedDomainReputation(domain string) ReviewedDomainReputation {
	result := ReviewedDomainReputation{Domain: domain}
	if !ValidReputationDomain(domain) {
		return result
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range s.order {
		msg := s.messages[id]
		if msg.ReviewStatus != "not_spam" && msg.ReviewStatus != "spam" {
			continue
		}
		authenticated := false
		for _, f := range msg.Findings {
			if f.Symbol == "DMARC_PASS" && strings.EqualFold(f.Source, "auth/dmarc/"+domain) {
				authenticated = true
				break
			}
		}
		if !authenticated {
			continue
		}
		if msg.ReviewStatus == "spam" {
			result.ConfirmedSpam++
		} else {
			result.ConfirmedHam++
		}
	}
	count := result.ConfirmedSpam + result.ConfirmedHam
	if count < 4 {
		return result
	}
	result.Ready = true
	if float64(result.ConfirmedSpam)/float64(count) >= 0.8 {
		result.Weight = 2
	}
	if float64(result.ConfirmedHam)/float64(count) >= 0.8 {
		result.Weight = -1
	}
	return result
}
