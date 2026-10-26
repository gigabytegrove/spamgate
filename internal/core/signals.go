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
