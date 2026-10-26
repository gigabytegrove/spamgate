package core

import (
	"sort"
	"strings"
)

// SignalPolicy controls an existing built-in detector. Enabled=false suppresses
// its finding, while Score changes its weight without altering the detector.
type SignalPolicy struct {
	Enabled bool    `json:"enabled"`
	Score   float64 `json:"score"`
}

type SignalDefinition struct {
	Symbol       string  `json:"symbol"`
	Source       string  `json:"source"`
	Description  string  `json:"description"`
	DefaultScore float64 `json:"default_score"`
	Enabled      bool    `json:"enabled"`
	Score        float64 `json:"score"`
	Customized   bool    `json:"customized"`
}

// BuiltinCatalog is derived from the exact symbols currently emitted in scan.go.
func BuiltinCatalog() []SignalDefinition {
	definitions := []SignalDefinition{
		{Symbol: "MISSING_FROM", Source: "builtin/header", Description: "Missing From header", DefaultScore: 2},
		{Symbol: "MISSING_DATE", Source: "builtin/header", Description: "Missing Date header", DefaultScore: 0.5},
		{Symbol: "UNKNOWN_RECIPIENT", Source: "builtin/envelope", Description: "No envelope recipient metadata", DefaultScore: 0.5},
		{Symbol: "MISSING_MESSAGE_ID", Source: "builtin/header", Description: "Missing Message-ID header", DefaultScore: 1},
		{Symbol: "EMPTY_HTML", Source: "builtin/mime", Description: "HTML-only content without usable text", DefaultScore: 0.5},
		{Symbol: "RISKY_ATTACHMENT", Source: "builtin/attachment", Description: "Potentially dangerous attachment extension", DefaultScore: 5},
		{Symbol: "DOUBLE_EXTENSION", Source: "builtin/attachment", Description: "Disguised executable attachment extension", DefaultScore: 4},
		{Symbol: "IP_URL", Source: "builtin/url", Description: "Link with an IP address instead of a hostname", DefaultScore: 2.5},
		{Symbol: "PUNYCODE_URL", Source: "builtin/url", Description: "Link containing punycode internationalized hostname", DefaultScore: 1.5},
		{Symbol: "LONG_HOSTNAME", Source: "builtin/url", Description: "Unusually long linked hostname", DefaultScore: 1},
		{Symbol: "MANY_LINK_DOMAINS", Source: "builtin/url", Description: "Message contains more than eight distinct linked domains", DefaultScore: 2},
	}
	definitions = append(definitions,
		SignalDefinition{Symbol: "FUZZY_SPAM", Source: "learning/fuzzy", Description: "Near-duplicate of administrator-trained spam (90-day retention)", DefaultScore: 6},
		SignalDefinition{Symbol: "FUZZY_HAM", Source: "learning/fuzzy", Description: "Near-duplicate of administrator-trained legitimate message", DefaultScore: -3},
		SignalDefinition{Symbol: "NEURAL_SPAM", Source: "learning/neural", Description: "Neural network predicts spam from historical detection symbols", DefaultScore: 3},
		SignalDefinition{Symbol: "NEURAL_HAM", Source: "learning/neural", Description: "Neural network predicts legitimate mail from historical detection symbols", DefaultScore: -2},
		SignalDefinition{Symbol: "BAYES_SPAM", Source: "learning/bayes", Description: "Locally trained Bayesian spam probability >=95%", DefaultScore: 3.5},
		SignalDefinition{Symbol: "BAYES_HAM", Source: "learning/bayes", Description: "Locally trained Bayesian spam probability <=5%", DefaultScore: -2},
	)
	definitions = append(definitions,
		SignalDefinition{Symbol: "R_SPF_ALLOW", Source: "auth/spf", Description: "Envelope domain SPF authorized client IP", DefaultScore: -1},
		SignalDefinition{Symbol: "R_SPF_FAIL", Source: "auth/spf", Description: "Envelope domain SPF hard failure", DefaultScore: 4},
		SignalDefinition{Symbol: "R_SPF_SOFTFAIL", Source: "auth/spf", Description: "Envelope domain SPF soft failure", DefaultScore: 1.5},
		SignalDefinition{Symbol: "R_SPF_PERMERROR", Source: "auth/spf", Description: "Invalid SPF DNS policy", DefaultScore: 1},
		SignalDefinition{Symbol: "R_DKIM_ALLOW", Source: "auth/dkim", Description: "Cryptographically valid DKIM signature", DefaultScore: -1},
		SignalDefinition{Symbol: "R_DKIM_REJECT", Source: "auth/dkim", Description: "Present DKIM signature failed verification", DefaultScore: 2},
		SignalDefinition{Symbol: "ARC_MALFORMED", Source: "auth/arc", Description: "ARC chain header structure invalid (informational; not cryptographic validation)", DefaultScore: 0},
		SignalDefinition{Symbol: "ARC_UNVERIFIED", Source: "auth/arc", Description: "ARC header chain present, not cryptographically validated", DefaultScore: 0},
		SignalDefinition{Symbol: "DMARC_PASS", Source: "auth/dmarc", Description: "From-domain aligned SPF or DKIM", DefaultScore: -1},
		SignalDefinition{Symbol: "DMARC_FAIL", Source: "auth/dmarc", Description: "Exact-domain DMARC policy authentication failed (base weight; multiplied by policy)", DefaultScore: 1},
		SignalDefinition{Symbol: "DMARC_PERMERROR", Source: "auth/dmarc", Description: "Invalid DMARC policy", DefaultScore: 1},
		SignalDefinition{Symbol: "CLAMAV_MALWARE", Source: "antivirus/clamav", Description: "ClamAV detected malware (forces rejection regardless of weight)", DefaultScore: 100},
	)
	for _, word := range suspiciousWords {
		symbol := "CONTENT_" + strings.ToUpper(strings.ReplaceAll(word.word, " ", "_"))
		definitions = append(definitions, SignalDefinition{Symbol: symbol, Source: "builtin/content", Description: "Message contains phrase: " + word.word, DefaultScore: word.weight})
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Symbol < definitions[j].Symbol })
	for i := range definitions {
		definitions[i].Enabled = true
		definitions[i].Score = definitions[i].DefaultScore
	}
	return definitions
}

func ConfiguredSignals(config Config) []SignalDefinition {
	all := BuiltinCatalog()
	for i := range all {
		if p, ok := config.SignalPolicies[all[i].Symbol]; ok {
			all[i].Enabled = p.Enabled
			all[i].Score = p.Score
			all[i].Customized = true
		}
	}
	return all
}
func IsBuiltinSymbol(symbol string) bool {
	for _, def := range BuiltinCatalog() {
		if def.Symbol == symbol {
			return true
		}
	}
	return false
}
