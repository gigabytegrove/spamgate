package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestInvalidDKIMSignaturesCannotMultiplyScore(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{Store: st, Resolver: stubDNS{}}
	var h strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&h, "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=k%d; c=relaxed/relaxed; h=from; bh=bad; b=bad\r\n", i)
	}
	raw := []byte("From: sender@example.org\r\nTo: receiver@example.org\r\nDate: Tue, 27 Oct 2026 12:00:00 -0400\r\nMessage-ID: <test@example.org>\r\n" + h.String() + "\r\nHello\r\n")
	got, err := s.Scan(context.Background(), Input{Raw: raw, Sender: "sender@example.org", Recipients: []string{"receiver@example.org"}, Connector: "simulation"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range got.Findings {
		if f.Symbol == "R_DKIM_REJECT" {
			count++
			if f.Score != 2 {
				t.Fatalf("unexpected DKIM penalty: %+v", f)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected only one capped DKIM penalty, got %d; score %.2f", count, got.Score)
	}
}
