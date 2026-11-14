package transport

import (
 "errors"
 "math"

 "github.com/gigabytegrove/spamgate/internal/core"
)

var errRspamdSymbolOverflow = errors.New("aggregated symbol score is not finite")

// rspamdSymbols aggregates repeated scanner findings without allowing finite
// individual scores to overflow into a non-JSON-representable total.
func rspamdSymbols(findings []core.Finding) (map[string]map[string]any, error) {
 symbols := make(map[string]map[string]any, len(findings))
 for _, f := range findings {
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
