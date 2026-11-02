package backup

import (
 "bytes"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "strings"
 "time"
)

// Keep the backup reader's accepted counter schema aligned with the native
// worker's delivery-policy state reader. Backup Verify must never certify an
// archive that the worker will refuse to load at its first cold startup.
const (
 backupPolicyMaxKeys = 20000
 backupPolicyMaxRateStamps = 200000
 backupPolicyMaxStampsPerKey = 100000
)

type backupPolicyState struct {
 Initialized bool `json:"initialized,omitempty"`
 Greylist map[string]time.Time `json:"greylist"`
 Rates map[string][]time.Time `json:"rates"`
}

func validBackupPolicyKey(key string) bool {
 if len(key) != 64 || strings.ToLower(key) != key { return false }
 _, err := hex.DecodeString(key)
 return err == nil
}

// The caller has already bounded the raw bytes and rejected ambiguous JSON.
// Do not expose individual keys or timestamps in errors.
func validateBackupPolicyStateSchema(raw []byte) (bool, error) {
 decoder := json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var state backupPolicyState
 if err := decoder.Decode(&state); err != nil {
  return false, errors.New("delivery policy backup state has invalid schema or timestamp")
 }
 var trailing any
 if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
  return false, errors.New("delivery policy backup state has trailing data")
 }
 if len(state.Greylist) > backupPolicyMaxKeys || len(state.Rates) > backupPolicyMaxKeys {
  return false, errors.New("delivery policy backup state exceeds key capacity")
 }
 for key, stamp := range state.Greylist {
  if !validBackupPolicyKey(key) || stamp.IsZero() {
   return false, errors.New("delivery policy backup state has invalid greylist key or timestamp")
  }
 }
 total := 0
 for key, stamps := range state.Rates {
  if !validBackupPolicyKey(key) || stamps == nil || len(stamps) > backupPolicyMaxStampsPerKey {
   return false, errors.New("delivery policy backup state has invalid rate key or count")
  }
  total += len(stamps)
  if total > backupPolicyMaxRateStamps {
   return false, errors.New("delivery policy backup state exceeds timestamp capacity")
  }
  for _, stamp := range stamps {
   if stamp.IsZero() {
    return false, errors.New("delivery policy backup state has invalid rate timestamp")
   }
  }
 }
 return state.Initialized, nil
}
