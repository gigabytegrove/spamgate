package core

import (
	"net/mail"
	"strings"
	"time"
)

const Version = "0.6.0-alpha.13"

type Finding struct {
	Symbol string  `json:"symbol"`
	Source string  `json:"source"`
	Detail string  `json:"detail"`
	Score  float64 `json:"score"`
}

// ScanCheck records what the scanner actually attempted, skipped, or found.
// It is stored with the message so later policy edits do not rewrite history.
type ScanCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // match, clear, skipped, error, info
	Detail string `json:"detail"`
}
type ScoringTrace struct {
	TagThreshold        float64     `json:"tag_threshold"`
	QuarantineThreshold float64     `json:"quarantine_threshold"`
	RejectThreshold     float64     `json:"reject_threshold"`
	ForcedAction        string      `json:"forced_action,omitempty"`
	Checks              []ScanCheck `json:"checks"`
}
type Message struct {
	ID             string        `json:"id"`
	Timestamp      time.Time     `json:"timestamp"`
	MessageID      string        `json:"message_id,omitempty"`
	Sender         string        `json:"sender"`
	Recipients     []string      `json:"recipients"`
	Subject        string        `json:"subject"`
	ClientIP       string        `json:"client_ip,omitempty"`
	IngestIP       string        `json:"ingest_ip,omitempty"`
	Connector      string        `json:"connector"`
	Size           int           `json:"size"`
	ScanDurationMS int64         `json:"scan_duration_ms,omitempty"`
	Score          float64       `json:"score"`
	Action         string        `json:"action"`
	Findings       []Finding     `json:"findings"`
	Scoring        *ScoringTrace `json:"scoring,omitempty"`
	OverrideBy     string        `json:"override_by,omitempty"`
	OverrideReason string        `json:"override_reason,omitempty"`
	OriginalAction string        `json:"original_action,omitempty"`
	Delivery       string        `json:"delivery,omitempty"`
	MTAQueueID     string        `json:"mta_queue_id,omitempty"` // Reported by Postfix Milter macro; unverified until queue is inspected
	MTAAction      string        `json:"mta_action,omitempty"`   // Command requested of MTA, not confirmed delivery
	MTAActionNote  string        `json:"mta_action_note,omitempty"`
	MTAActionState string        `json:"mta_action_state,omitempty"` // requested or unavailable; never confirmed by Milter
	// HeaderSnapshot is a transient ingestion-only copy. It is deliberately excluded
	// from events.jsonl and from ALL ordinary API responses. The original body is
	// never retained for this inspector feature.
	HeaderSnapshot  []byte    `json:"-"`
	HeaderTruncated bool      `json:"-"`
	ReviewStatus    string    `json:"review_status,omitempty"`
	ReviewedBy      string    `json:"reviewed_by,omitempty"`
	ReviewedAt      time.Time `json:"reviewed_at,omitempty"`
}
type Rule struct {
	Owner     string    `json:"owner,omitempty"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Score     float64   `json:"score"`
	Action    string    `json:"action,omitempty"`
	Enabled   bool      `json:"enabled"`
	Priority  int       `json:"priority,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}
type DNSList struct {
	Zone    string  `json:"zone"`
	Kind    string  `json:"kind,omitempty"` // empty/ip, domain, url
	Score   float64 `json:"score"`
	Enabled bool    `json:"enabled"`
}
type User struct {
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	Role         string `json:"role"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"password_hash"`
}
type Token struct {
	Name    string    `json:"name"`
	Hash    string    `json:"hash"`
	Scope   string    `json:"scope"`
	Created time.Time `json:"created"`
}

// RecipientPolicy overrides action thresholds for exactly one envelope recipient.
// Multi-recipient transactions with different policies remain on global policy;
// a Milter cannot safely apply different SMTP actions to one transaction.
type RecipientPolicy struct {
	Mailbox             string  `json:"mailbox"`
	TagThreshold        float64 `json:"tag_threshold"`
	QuarantineThreshold float64 `json:"quarantine_threshold"`
	RejectThreshold     float64 `json:"reject_threshold"`
}

func (p RecipientPolicy) Valid() bool {
	if len(p.Mailbox) > 254 || strings.TrimSpace(p.Mailbox) != p.Mailbox || strings.ContainsAny(p.Mailbox, "\r\n<> ") {
		return false
	}
	address, err := mail.ParseAddress(p.Mailbox)
	return err == nil && address.Address == p.Mailbox && strings.Count(p.Mailbox, "@") == 1 &&
		p.TagThreshold >= 0 && p.QuarantineThreshold > p.TagThreshold &&
		p.RejectThreshold > p.QuarantineThreshold && p.RejectThreshold <= 1000
}

type Settings struct {
	SiteName             string  `json:"site_name"`
	TagThreshold         float64 `json:"tag_threshold"`
	QuarantineThreshold  float64 `json:"quarantine_threshold"`
	RejectThreshold      float64 `json:"reject_threshold"`
	DNSBLEnabled         bool    `json:"dnsbl_enabled"`
	GreylistEnabled      bool    `json:"greylist_enabled"`
	GreylistWaitMinutes  int     `json:"greylist_wait_minutes"`
	RateLimitEnabled     bool    `json:"rate_limit_enabled"`
	RateLimitPerHour     int     `json:"rate_limit_per_hour"`
	QuarantineMode       string  `json:"quarantine_mode"`     // hold (default) or junk (Milter header plus Sieve)
	SubjectRewrite       bool    `json:"subject_rewrite"`     // off by default: changes can break DKIM
	ReviewedReputation   bool    `json:"reviewed_reputation"` // opt-in, manual review + DMARC pass required
	PhishingLinks        bool    `json:"phishing_links"`
	AttachmentInspection bool    `json:"attachment_inspection"`
	ExternalFuzzyEnabled bool    `json:"external_fuzzy_enabled"`
	ThreatFeedEnabled    bool    `json:"threat_feed_enabled"`
	RetentionDays        int     `json:"retention_days"`
	MaxHistory           int     `json:"max_history"`
}

// Onboarding is a saved configuration plan, not proof of live mail flow.
type Onboarding struct {
	// Completed means the configuration choices were saved, NOT that mail is protected.
	Completed bool   `json:"completed"`
	Server    string `json:"server"`
	Mode      string `json:"mode"`
	Policy    string `json:"policy"`
	// Probe is an administrator-only, time-limited challenge for real MTA traffic.
	Probe        string    `json:"probe,omitempty"`
	ProbeStarted time.Time `json:"probe_started,omitempty"`
	ProbeExpires time.Time `json:"probe_expires,omitempty"`
	VerifiedID   string    `json:"verified_id,omitempty"`
	Activated    bool      `json:"activated"`
	ActivatedAt  time.Time `json:"activated_at,omitempty"`
}
type Config struct {
	Onboarding        Onboarding              `json:"onboarding"`
	Settings          Settings                `json:"settings"`
	SignalPolicies    map[string]SignalPolicy `json:"signal_policies"`
	Rules             []Rule                  `json:"rules"`
	DNSLists          []DNSList               `json:"dns_lists"`
	RecipientPolicies []RecipientPolicy       `json:"recipient_policies,omitempty"`
	Users             []User                  `json:"users"`
	Tokens            []Token                 `json:"tokens"`
	SetupComplete     bool                    `json:"setup_complete"`
}

func DefaultConfig() Config {
	return Config{Settings: Settings{SiteName: "SpamGate", TagThreshold: 5, QuarantineThreshold: 10, RejectThreshold: 20, RetentionDays: 30, MaxHistory: 10000, GreylistWaitMinutes: 5, RateLimitPerHour: 240, QuarantineMode: "hold"},
		SignalPolicies: map[string]SignalPolicy{}, Rules: []Rule{}, DNSLists: []DNSList{{Zone: "zen.spamhaus.org", Score: 5, Enabled: false}}}
}
func (s Settings) Valid() bool {
	return s.SiteName == "SpamGate" && s.RetentionDays >= 1 && s.RetentionDays <= 3650 && s.MaxHistory >= 100 && s.MaxHistory <= 500000 && s.TagThreshold >= 0 && s.QuarantineThreshold > s.TagThreshold && s.RejectThreshold > s.QuarantineThreshold && s.RejectThreshold <= 1000 &&
		(s.QuarantineMode == "" || s.QuarantineMode == "hold" || s.QuarantineMode == "junk") &&
		(s.GreylistWaitMinutes == 0 || (s.GreylistWaitMinutes >= 1 && s.GreylistWaitMinutes <= 120)) &&
		(s.RateLimitPerHour == 0 || (s.RateLimitPerHour >= 10 && s.RateLimitPerHour <= 100000))
}
