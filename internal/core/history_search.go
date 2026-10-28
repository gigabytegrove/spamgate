package core

import (
	"errors"
	"strings"
	"time"
)

type HistoryQuery struct {
	Text      string
	Action    string
	Sender    string
	Recipient string
	From      time.Time
	To        time.Time
	Offset    int
	Limit     int
}
type HistoryResult struct {
	Total  int       `json:"total"`
	Offset int       `json:"offset"`
	Limit  int       `json:"limit"`
	Items  []Message `json:"items"`
}

func (s *Store) SearchHistory(query HistoryQuery, mailbox string) (HistoryResult, error) {
	if query.Offset < 0 || query.Limit < 1 || query.Limit > 500 || query.Offset > 500000 {
		return HistoryResult{}, errors.New("invalid pagination")
	}
	if query.Action != "" && query.Action != "all" && query.Action != "accept" && query.Action != "tag" && query.Action != "quarantine" && query.Action != "reject" {
		return HistoryResult{}, errors.New("invalid action")
	}
	query.Text = strings.ToLower(strings.TrimSpace(query.Text))
	query.Sender = strings.ToLower(strings.TrimSpace(query.Sender))
	query.Recipient = strings.ToLower(strings.TrimSpace(query.Recipient))
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := HistoryResult{Offset: query.Offset, Limit: query.Limit, Items: []Message{}}
	for i := len(s.order) - 1; i >= 0; i-- {
		m := s.messages[s.order[i]]
		if mailbox != "" && !containsAddress(m.Recipients, mailbox) {
			continue
		}
		if query.Action != "" && query.Action != "all" && query.Action != m.Action {
			continue
		}
		if query.Sender != "" && !strings.Contains(strings.ToLower(m.Sender), query.Sender) {
			continue
		}
		if query.Recipient != "" {
			recipients := strings.Join(m.Recipients, ",")
			if mailbox != "" {
				recipients = mailbox
			} // never query unseen co-recipients
			if !strings.Contains(strings.ToLower(recipients), query.Recipient) {
				continue
			}
		}
		if !query.From.IsZero() && m.Timestamp.Before(query.From) {
			continue
		}
		if !query.To.IsZero() && m.Timestamp.After(query.To) {
			continue
		}
		if query.Text != "" {
			visibleRecipients := strings.Join(m.Recipients, ",")
			if mailbox != "" {
				visibleRecipients = mailbox
			}
			searchFields := []string{m.ID, m.MessageID, m.MTAQueueID, m.Sender, m.Subject, m.Action, m.Connector, m.ClientIP, visibleRecipients}
			for _, finding := range m.Findings {
				searchFields = append(searchFields, finding.Symbol, finding.Source, finding.Detail)
			}
			haystack := strings.ToLower(strings.Join(searchFields, " "))
			if !strings.Contains(haystack, query.Text) {
				continue
			}
		}
		if result.Total >= query.Offset && len(result.Items) < query.Limit {
			if mailbox != "" {
				m.Recipients = []string{mailbox}
			}
			result.Items = append(result.Items, m)
		}
		result.Total++
	}
	return result, nil
}
