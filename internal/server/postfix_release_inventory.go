package server

import (
    "errors"
    "strings"
)

// validatePostfixReleaseInventory rejects ambiguous inventory supplied by
// either the native postqueue reader or an injected provider. A queue ID is
// only usable as authorization evidence if it occurs exactly once globally.
func validatePostfixReleaseInventory(items []PostfixHeld) error {
    seen := make(map[string]struct{}, len(items))
    for _, item := range items {
        if !validPostfixEvidenceID(item.QueueID) || strings.EqualFold(item.QueueID, "ALL") {
            return errors.New("invalid Postfix queue inventory identifier")
        }
        if _, exists := seen[item.QueueID]; exists {
            return errors.New("ambiguous Postfix queue inventory identifier")
        }
        seen[item.QueueID] = struct{}{}
        if item.ArrivalTime <= 0 || item.MessageSize < 0 || item.RecipientCount < 1 ||
            item.RecipientsTruncated || item.RecipientCount != len(item.Recipients) {
            return errors.New("incomplete Postfix queue ownership inventory")
        }
        for _, address := range item.Recipients {
            if strings.TrimSpace(address) == "" {
                return errors.New("missing Postfix queue recipient")
            }
        }
    }
    return nil
}
