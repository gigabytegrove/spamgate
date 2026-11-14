package transport

import (
 "errors"
 "math"
 "strings"
 "unicode/utf8"

 "github.com/gigabytegrove/spamgate/internal/core"
)

var (
 errRspamdSymbolOverflow = errors.New("aggregated symbol score is not finite")
 errRspamdSymbolMetadata = errors.New("scanner finding metadata is invalid")
)

// Bound the amount of untrusted scanner finding metadata copied into an MTA
// response. Reject ambiguous symbol keys rather than silently overwriting
// or emitting a response with control characters.
const (
 rspamdMaxFindings = 4096
 rspamdMaxSymbolBytes = 256
 rspamdMaxDetailBytes = 4096
 rspamdMaxSourceBytes = 256
)

func rspamdValidFindingText(value string, limit int, allowEmpty bool) bool {
 if len(value) > limit || (!allowEmpty && value == "") || !utf8.ValidString(value) {
  return false
 }
 for _, r := range value {
  if r < 0x20 || r == 0x7f {
   return false
  }
 }
 return true
}

func rspamdValidSymbol(value string) bool {
 if !rspamdValidFindingText(value, rspamdMaxSymbolBytes, false) {
  return false
 }
 for _, r := range value {
  if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
   (r >= '0' && r <= '9') || r == '_') {
   return false
  }
 }
 return !strings.HasPrefix(value, "_")
}

// rspamdSymbols aggregates repeated findings and validates the complete
// symbol payload before the caller commits scan history.
func rspamdSymbols(findings []core.Finding) (map[string]map[string]any, error) {
 if len(findings) > rspamdMaxFindings {
  return nil, errRspamdSymbolMetadata
 }
 symbols := make(map[string]map[string]any, len(findings))
 for _, f := range findings {
  if !rspamdValidSymbol(f.Symbol) ||
   !rspamdValidFindingText(f.Detail, rspamdMaxDetailBytes, true) ||
   !rspamdValidFindingText(f.Source, rspamdMaxSourceBytes, true) {
   return nil, errRspamdSymbolMetadata
  }
  if math.IsNaN(f.Score) || math.IsInf(f.Score, 0) {
   return nil, errRspamdSymbolOverflow
  }
  if current, ok := symbols[f.Symbol]; ok {
   total := current["score"].(float64) + f.Score
   if math.IsNaN(total) || math.IsInf(total, 0) {
    return nil, errRspamdSymbolOverflow
   }
   current["score"] = total
   current["options"] = append(current["options"].([]string), f.Detail)
   continue
  }
  symbols[f.Symbol] = map[string]any{
   "name": f.Symbol,
   "score": f.Score,
   "options": []string{f.Detail},
   "description": f.Source,
  }
 }
 return symbols, nil
}
