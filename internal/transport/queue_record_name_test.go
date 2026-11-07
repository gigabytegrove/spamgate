package transport

import (
    "strings"
    "testing"
)

func TestValidQueueRecordName(t *testing.T) {
    valid := strings.Repeat("a", 32) + ".json"
    if !validQueueRecordName(valid) { t.Fatal("canonical queue filename rejected") }
    invalid := []string{
        "", ".", "..", "../" + valid, valid + "/child",
        strings.Repeat("A", 32) + ".json",
        strings.Repeat("g", 32) + ".json",
        strings.Repeat("a", 31) + ".json",
        strings.Repeat("a", 32) + ".JSON",
        strings.Repeat("a", 32) + ".json.bak",
        strings.Repeat("a", 32) + "\x00.json",
        ".pending-" + strings.Repeat("a", 32),
    }
    for _, name := range invalid {
        if validQueueRecordName(name) { t.Errorf("unsafe record name accepted: %q", name) }
    }
}
