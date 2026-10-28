package server

import (
	"strings"
	"testing"
)

func TestPostfixHoldInventorySeparatesQueueTypes(t *testing.T) {
	content := `{"queue_name":"active","queue_id":"A1234","sender":"send@example.org","recipients":[{"address":"user@example.org"}]}
{"queue_name":"hold","queue_id":"C6B9EF49","sender":"send@example.org","arrival_time":1793100000,"message_size":1234,"recipients":[{"address":"user@example.org"}]}
`
	holds, err := parsePostfixHold([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 1 || holds[0].QueueID != "C6B9EF49" || holds[0].Recipients[0] != "user@example.org" {
		t.Fatalf("wrong queue inventory: %+v", holds)
	}
	for _, raw := range []string{`{"queue_name":"hold",`, `{"queue_name":"hold","queue_id":"../escape"}`} {
		if _, err := parsePostfixHold([]byte(raw)); err == nil {
			t.Fatalf("invalid input accepted: %s", strings.TrimSpace(raw))
		}
	}
}
