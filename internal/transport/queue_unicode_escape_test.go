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

// encoding/json replaces unpaired surrogates with U+FFFD. The mutation below
// preserves both decoded digests, proving the original validation bypass.
func TestQueueRejectsLossyUnicodeEscapeWithMatchingDigests(t *testing.T) {
    sends := 0
    q, store, dir := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
        sends++
        return nil
    })
    m := core.Message{
        ID: core.ID(), Sender: "sender@example.invalid",
        Recipients: []string{"recipient@example.invalid"},
        Subject: "replacement \ufffd character", Action: "accept",
    }
    if err := q.Enqueue(m, []byte("Subject: original\r\n\r\nbody")); err != nil {
        t.Fatal(err)
    }
    path := q.path(m.ID)
    original, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    needle := []byte("replacement \ufffd character")
    if !bytes.Contains(original, needle) { t.Fatal("fixture missing canonical replacement rune") }
    mutated := bytes.Replace(original, needle, []byte(`replacement \ud800 character`), 1)
    var decoded spoolRecord
    if err := json.Unmarshal(mutated, &decoded); err != nil { t.Fatal(err) }
    if decoded.Subject != m.Subject || decoded.IntegritySHA256 != spoolDigest(decoded) || decoded.StateSHA256 != spoolStateDigest(decoded) {
        t.Fatal("fixture did not reproduce matching-digest lossy JSON decoding")
    }
    if err := os.WriteFile(path, mutated, 0600); err != nil { t.Fatal(err) }
    if _, err := q.Snapshot(); err == nil || !strings.Contains(err.Error(), "Unicode escape") {
        t.Fatalf("accepted malformed surrogate in spool: %v", err)
    }
    if err := q.ProcessDue(context.Background()); err == nil || sends != 0 {
        t.Fatalf("relayed malformed original: sends=%d err=%v", sends, err)
    }
    if _, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return nil }); err == nil {
        t.Fatal("restart accepted malformed surrogate")
    }
    preserved, err := os.ReadFile(path)
    if err != nil || !bytes.Equal(preserved, mutated) { t.Fatalf("forensic original changed: %v", err) }
}
