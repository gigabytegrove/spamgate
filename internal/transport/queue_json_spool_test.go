package transport

import (
    "bytes"
    "context"
    "encoding/json"
    "os"
    "strings"
    "testing"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// Contradictory keys can decode to the same final value as a clean record,
// so a digest over the decoded struct alone cannot detect this tampering.
func TestQueueAmbiguousJSONNeverReachesRelay(t *testing.T) {
    for _, tc := range []struct {
        name string
        old []byte
        replacement []byte
    }{
        {"duplicate mutable state", []byte(`"state":"queued"`), []byte(`"state":"dead","state":"queued"`)},
        {"casefold mutable state", []byte(`"state":"queued"`), []byte(`"State":"dead","state":"queued"`)},
        {"unicode simplefold mutable state", []byte(`"state":"queued"`), []byte(`"ſtate":"dead","state":"queued"`)},
        {"unicode escaped simplefold mutable state", []byte(`"state":"queued"`), []byte(`"\\u017ftate":"dead","state":"queued"`)},
        {"escaped mutable state", []byte(`"state":"queued"`), []byte(`"st\u0061te":"dead","state":"queued"`)},
        {"duplicate immutable scan", []byte(`"scan":{"id":`), []byte(`"scan":{"id":"forged","id":`)},
    } {
        t.Run(tc.name, func(t *testing.T) {
            sends := 0
            q, store, dir := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
                sends++
                return nil
            })
            msg := core.Message{
                ID: core.ID(), Sender: "sender@example.invalid",
                Recipients: []string{"recipient@example.invalid"}, Action: "accept",
            }
            if err := q.Enqueue(msg, []byte("Subject: intact\r\n\r\noriginal")); err != nil { t.Fatal(err) }
            path := q.path(msg.ID)
            original, err := os.ReadFile(path)
            if err != nil { t.Fatal(err) }
            if !bytes.Contains(original, tc.old) { t.Fatalf("fixture missing %q", tc.old) }
            mutated := bytes.Replace(original, tc.old, tc.replacement, 1)
            if err := os.WriteFile(path, mutated, 0600); err != nil { t.Fatal(err) }
            // The ordinary decoder still sees matching digests after the
            // last-value-wins parse, proving the original bypass.
            var decoded spoolRecord
            if err := json.Unmarshal(mutated, &decoded); err != nil { t.Fatal(err) }
            if decoded.IntegritySHA256 != spoolDigest(decoded) || decoded.StateSHA256 != spoolStateDigest(decoded) {
                t.Fatal("fixture did not reproduce a matching-digest ambiguous record")
            }
            if _, err := q.Snapshot(); err == nil || !strings.Contains(err.Error(), "duplicate") {
                t.Fatalf("ambiguous spool accepted: %v", err)
            }
            if err := q.ProcessDue(context.Background()); err == nil || sends != 0 {
                t.Fatalf("ambiguous spool relayed: err=%v sends=%d", err, sends)
            }
            if _, err := os.Stat(path); err != nil { t.Fatalf("original removed: %v", err) }
            if _, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return nil }); err == nil {
                t.Fatal("restart accepted ambiguous spool")
            }
        })
    }
}
