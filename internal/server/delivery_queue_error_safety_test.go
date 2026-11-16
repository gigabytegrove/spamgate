package server

import (
    "strings"
    "testing"
)

// Backend failures can embed filesystem paths, private sender identities and
// privileged command output. No such information belongs in an API response.
func TestDeliveryQueueMutationFailuresDoNotExposeBackendDetails(t *testing.T) {
    secret := "/opt/spamgate/data/spool/tenant-private/secret.eml"
    for _, tc := range []struct{ action, want string }{
        {"retry", "retry"},
        {"discard", "discard"},
        {"unexpected", "operation"},
    } {
        got := deliveryQueueMutationFailure(tc.action)
        if !strings.Contains(strings.ToLower(got), tc.want) {
            t.Errorf("%s: missing action context: %q", tc.action, got)
        }
        if strings.Contains(got, secret) || strings.Contains(got, "permission denied") {
            t.Errorf("%s: leaked backend detail: %q", tc.action, got)
        }
        if len(got) == 0 || len(got) > 180 {
            t.Errorf("%s: invalid safe response length %d", tc.action, len(got))
        }
    }
}
