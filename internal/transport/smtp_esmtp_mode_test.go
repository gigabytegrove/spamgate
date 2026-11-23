package transport

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTPGreetingMailOptionBoundary(t *testing.T) {
	for _, tc := range []struct {
		esmtp bool
		line string
		wantError bool
	}{
		{false, "MAIL FROM:<sender@example.org>", false},
		{false, "MAIL FROM:<>", false},
		{false, "MAIL FROM:<sender@example.org> SIZE=100", true},
		{false, "MAIL FROM:<sender@example.org> BODY=8BITMIME", true},
		{true, "MAIL FROM:<sender@example.org> SIZE=100", false},
		{true, "MAIL FROM:<sender@example.org> BODY=8BITMIME", false},
		{false, "MAIL FROM:invalid", true},
	} {
		if err := validateSMTPGreetingMailOptions(tc.esmtp, tc.line); (err != nil) != tc.wantError {
			t.Errorf("esmtp=%v line=%q err=%v wantError=%v", tc.esmtp, tc.line, err, tc.wantError)
		}
	}
}

func TestSMTPGreetingModeResetAndExtensionNegotiation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil { return }
		_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
		(&SMTP{CIDRs: []*net.IPNet{cidr}}).handle(conn)
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5*time.Second)); err != nil { t.Fatal(err) }
	reader := bufio.NewReader(conn)
	expect := func(prefix string) {
		t.Helper()
		line, e := reader.ReadString('\n')
		if e != nil { t.Fatal(e) }
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("response %q, expected prefix %q", line, prefix)
		}
	}
	send := func(command string) {
		t.Helper()
		if _, e := fmt.Fprintf(conn, "%s\r\n", command); e != nil { t.Fatal(e) }
	}
	expect("220 ")
	send("HELO mail.example.org")
	expect("250 ")
	send("XFORWARD ADDR=192.0.2.20")
	expect("503 ")
	send("MAIL FROM:<sender@example.org> SIZE=50")
	expect("501 ")
	send("RCPT TO:<user@example.org>")
	expect("503 ")
	send("MAIL FROM:<sender@example.org>")
	expect("250 ")
	send("RSET")
	expect("250 ")
	send("EHLO mail.example.org")
	for _, prefix := range []string{"250-", "250-", "250-", "250 "} { expect(prefix) }
	send("XFORWARD ADDR=192.0.2.20")
	expect("250 ")
	send("MAIL FROM:<sender@example.org> SIZE=50")
	expect("250 ")
	send("HELO mail.example.org")
	expect("250 ")
	send("XFORWARD ADDR=192.0.2.21")
	expect("503 ")
	send("MAIL FROM:<sender@example.org> BODY=8BITMIME")
	expect("501 ")
	send("MAIL FROM:<>")
	expect("250 ")
	send("QUIT")
	expect("221 ")
	select {
	case <-done:
	case <-time.After(2*time.Second): t.Fatal("SMTP handler did not exit")
	}
}
