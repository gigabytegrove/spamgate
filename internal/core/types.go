package core

import "time"

const Version = "0.1.0-alpha.1"

type Finding struct {
	Symbol string  `json:"symbol"`
	Source string  `json:"source"`
	Detail string  `json:"detail"`
	Score  float64 `json:"score"`
}
type Message struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	MessageID      string    `json:"message_id,omitempty"`
	Sender         string    `json:"sender"`
	Recipients     []string  `json:"recipients"`
	Subject        string    `json:"subject"`
	ClientIP       string    `json:"client_ip,omitempty"`
	IngestIP       string    `json:"ingest_ip,omitempty"`
	Connector      string    `json:"connector"`
	Size           int       `json:"size"`
	Score          float64   `json:"score"`
	Action         string    `json:"action"`
	Findings       []Finding `json:"findings"`
	OverrideBy     string    `json:"override_by,omitempty"`
	OverrideReason string    `json:"override_reason,omitempty"`
	OriginalAction string    `json:"original_action,omitempty"`
	Delivery       string    `json:"delivery,omitempty"`
}
type Rule struct {
	Owner   string  `json:"owner,omitempty"`
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	Value   string  `json:"value"`
	Score   float64 `json:"score"`
	Action  string  `json:"action,omitempty"`
	Enabled bool    `json:"enabled"`
}
type DNSList struct {
	Zone    string  `json:"zone"`
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
type Settings struct {
	SiteName            string  `json:"site_name"`
	TagThreshold        float64 `json:"tag_threshold"`
	QuarantineThreshold float64 `json:"quarantine_threshold"`
	RejectThreshold     float64 `json:"reject_threshold"`
	DNSBLEnabled        bool    `json:"dnsbl_enabled"`
	RetentionDays       int     `json:"retention_days"`
	MaxHistory          int     `json:"max_history"`
}
type Config struct {
	Settings      Settings  `json:"settings"`
	Rules         []Rule    `json:"rules"`
	DNSLists      []DNSList `json:"dns_lists"`
	Users         []User    `json:"users"`
	Tokens        []Token   `json:"tokens"`
	SetupComplete bool      `json:"setup_complete"`
}

func DefaultConfig() Config {
	return Config{Settings: Settings{SiteName: "SpamGate", TagThreshold: 5, QuarantineThreshold: 10, RejectThreshold: 20, RetentionDays: 30, MaxHistory: 10000},
		Rules: []Rule{}, DNSLists: []DNSList{{Zone: "zen.spamhaus.org", Score: 5, Enabled: false}}}
}
func (s Settings) Valid() bool {
	return s.SiteName != "" && s.RetentionDays >= 1 && s.RetentionDays <= 3650 && s.MaxHistory >= 100 && s.MaxHistory <= 500000 && s.TagThreshold >= 0 && s.QuarantineThreshold > s.TagThreshold && s.RejectThreshold > s.QuarantineThreshold && s.RejectThreshold <= 1000
}
