package transport

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSMTPCommandDeadline(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cases := []struct {
		name string
		session time.Duration
		idle time.Duration
		want time.Duration
	}{
		{"idle shorter", 4*time.Minute, 30*time.Second, 30*time.Second},
		{"session shorter", 10*time.Second, 30*time.Second, 10*time.Second},
		{"equal", 30*time.Second, 30*time.Second, 30*time.Second},
		{"zero idle never extends", 30*time.Second, 0, 30*time.Second},
		{"expired session", -time.Second, 30*time.Second, -time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := smtpCommandDeadline(now, now.Add(tc.session), tc.idle)
			if want := now.Add(tc.want); !got.Equal(want) {
				t.Fatalf("deadline=%v want=%v", got, want)
			}
		})
	}
}

func TestSMTPIdleCommandReadTimesOut(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	now := time.Now()
	if err := server.SetReadDeadline(smtpCommandDeadline(now, now.Add(time.Second), 20*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := readSMTPCommand(bufio.NewReader(server))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected network timeout, got %v", err)
	}
}

func TestSMTPClosedCommandReadIsNotTimeout(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	_ = peer.Close()
	_, err := readSMTPCommand(bufio.NewReader(server))
	var netErr net.Error
	if !errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("expected EOF without timeout, got %v", err)
	}
}
