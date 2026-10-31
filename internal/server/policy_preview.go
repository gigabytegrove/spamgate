package server

// Threshold-only policy replay against saved score evidence. No SMTP action,
// training, database mutation or live mail scan can occur through this endpoint.

import (
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/gigabytegrove/spamgate/internal/core"
)

type policyPreviewRequest struct {
	TagThreshold        float64                 `json:"tag_threshold"`
	QuarantineThreshold float64                 `json:"quarantine_threshold"`
	RejectThreshold     float64                 `json:"reject_threshold"`
	RecipientPolicies   *[]core.RecipientPolicy `json:"recipient_policies,omitempty"`
	Limit               int                     `json:"limit"`
}
type policyPreviewItem struct {
	ID                 string  `json:"id"`
	Score              float64 `json:"score"`
	HistoricalAction   string  `json:"historical_action"`
	HypotheticalAction string  `json:"hypothetical_action"`
	Changed            bool    `json:"changed"`
	Forced             bool    `json:"forced"`
	PolicySource       string  `json:"policy_source"`
	Note               string  `json:"note,omitempty"`
}

type policyPreviewTotals struct {
	Examined               int `json:"examined"`
	Changed                int `json:"changed"`
	WouldAccept            int `json:"would_accept"`
	WouldTag               int `json:"would_tag"`
	WouldQuarantine        int `json:"would_quarantine"`
	WouldReject            int `json:"would_reject"`
	ForcedPreserved        int `json:"forced_preserved"`
	MultiRecipientFallback int `json:"multi_recipient_fallback"`
}

func validatePreview(p policyPreviewRequest) error {
	if math.IsNaN(p.TagThreshold) || math.IsInf(p.TagThreshold, 0) || math.IsNaN(p.QuarantineThreshold) || math.IsInf(p.QuarantineThreshold, 0) || math.IsNaN(p.RejectThreshold) || math.IsInf(p.RejectThreshold, 0) || p.TagThreshold < 0 || p.QuarantineThreshold <= p.TagThreshold || p.RejectThreshold <= p.QuarantineThreshold || p.RejectThreshold > 1000 {
		return fmt.Errorf("thresholds must be finite, ascending and between 0 and 1000")
	}
	if p.Limit < 1 || p.Limit > 500 {
		return fmt.Errorf("preview limit must be between 1 and 500")
	}
	if p.RecipientPolicies != nil {
		if len(*p.RecipientPolicies) > 200 {
			return fmt.Errorf("too many recipient policies")
		}
		seen := map[string]bool{}
		for _, x := range *p.RecipientPolicies {
			if !x.Valid() {
				return fmt.Errorf("invalid mailbox policy")
			}
			k := strings.ToLower(x.Mailbox)
			if seen[k] {
				return fmt.Errorf("duplicate mailbox policy")
			}
			seen[k] = true
		}
	}
	return nil
}
func policyDecision(score, tag, quarantine, reject float64) string {
	switch {
	case score >= reject:
		return "reject"
	case score >= quarantine:
		return "quarantine"
	case score >= tag:
		return "tag"
	default:
		return "accept"
	}
}
func previewOne(m core.Message, p policyPreviewRequest, policies []core.RecipientPolicy) policyPreviewItem {
	result := policyPreviewItem{ID: m.ID, Score: m.Score, HistoricalAction: m.Action, PolicySource: "global"}
	selected := core.SelectRecipientThresholds(core.Settings{
		TagThreshold: p.TagThreshold, QuarantineThreshold: p.QuarantineThreshold, RejectThreshold: p.RejectThreshold,
	}, policies, m.Recipients)
	result.PolicySource = selected.Source
	if selected.Source == "global_multi_recipient" {
		result.Note = "Conflicting effective recipient thresholds; global thresholds used for this SMTP transaction"
	}
	result.HypotheticalAction = policyDecision(m.Score, selected.TagThreshold, selected.QuarantineThreshold, selected.RejectThreshold)
	if m.Scoring != nil && m.Scoring.ForcedAction != "" {
		result.Forced = true
		result.HypotheticalAction = m.Scoring.ForcedAction
		result.Note = "Historical forced rule action retained; rules are not re-evaluated"
	}
	result.Changed = result.HypotheticalAction != result.HistoricalAction
	return result
}
func (s *Server) previewPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	var in policyPreviewRequest
	if err := decode(r, &in); err != nil {
		fail(w, 400, "Invalid policy preview input")
		return
	}
	if err := validatePreview(in); err != nil {
		fail(w, 400, err.Error())
		return
	}
	policies := s.Store.Config().RecipientPolicies
	if in.RecipientPolicies != nil {
		policies = *in.RecipientPolicies
	}
	history, err := s.Store.SearchHistory(core.HistoryQuery{Limit: in.Limit}, "")
	if err != nil {
		fail(w, 503, "History query unavailable")
		return
	}
	items := make([]policyPreviewItem, 0, len(history.Items))
	totals := policyPreviewTotals{}
	for _, m := range history.Items {
		result := previewOne(m, in, policies)
		items = append(items, result)
		totals.Examined++
		if result.Changed {
			totals.Changed++
		}
		if result.Forced {
			totals.ForcedPreserved++
		}
		if result.PolicySource == "global_multi_recipient" {
			totals.MultiRecipientFallback++
		}
		switch result.HypotheticalAction {
		case "accept":
			totals.WouldAccept++
		case "tag":
			totals.WouldTag++
		case "quarantine":
			totals.WouldQuarantine++
		case "reject":
			totals.WouldReject++
		}
	}
	jsonReply(w, http.StatusOK, map[string]any{
		"simulation": true, "persisted": false, "mail_sent": false, "configuration_changed": false,
		"candidate": in, "total_retained_matching": history.Total, "totals": totals, "items": items,
		"limitations": []string{"Replays saved final scores against candidate thresholds; it does not re-scan messages or recalculate SPF, DKIM, DMARC, MIME, learning, or custom rule matches.", "Historical forced verdicts remain forced; rule edits, overrides and recipient splitting cannot be predicted from a score alone.", "Results are hypothetical scanner verdicts, not evidence that Postfix held, rejected, or delivered messages."},
	})
}
