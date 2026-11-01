package core

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func dnsReplyFixture(domain string, rcode uint16, records ...[]byte) []byte {
	question, err := dmarcDNSQuestion(domain)
	if err != nil {
		panic(err)
	}
	reply := make([]byte, 12, 12+len(question)+512)
	binary.BigEndian.PutUint16(reply[:2], 0x5a5a)
	binary.BigEndian.PutUint16(reply[2:4], 0x8180|rcode)
	binary.BigEndian.PutUint16(reply[4:6], 1)
	reply = append(reply, question...)
	for _, record := range records {
		reply = append(reply, record...)
	}
	return reply
}

func dnsTestRR(owner []byte, kind uint16, ttl uint32, data []byte) []byte {
	rr := append([]byte(nil), owner...)
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header[0:2], kind)
	binary.BigEndian.PutUint16(header[2:4], 1)
	binary.BigEndian.PutUint32(header[4:8], ttl)
	binary.BigEndian.PutUint16(header[8:10], uint16(len(data)))
	rr = append(rr, header...)
	return append(rr, data...)
}

func TestDMARCDNSCompleteNegativeResponseSections(t *testing.T) {
	domain := "sender.example.org"
	soa := dnsTestRR([]byte{0xc0, 0x0c}, 6, 60, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	opt := dnsTestRR([]byte{0}, 41, 0, nil)
	reply := dnsReplyFixture(domain, 3, soa, opt)
	binary.BigEndian.PutUint16(reply[8:10], 1)
	binary.BigEndian.PutUint16(reply[10:12], 1)
	if rcode, truncated, err := dmarcDNSRCODE(reply, 0x5a5a, domain); err != nil || truncated || rcode != 3 {
		t.Fatalf("valid SOA+OPT NXDOMAIN rejected: rcode=%d truncated=%v err=%v", rcode, truncated, err)
	}
}

func TestDMARCDNSRejectsContradictoryAndMalformedNegativeReplies(t *testing.T) {
	domain := "sender.example.org"
	opt := dnsTestRR([]byte{0}, 41, 0, nil)
	tests := []struct {
		name  string
		reply func() []byte
	}{
		{"trailing junk", func() []byte { return append(dnsReplyFixture(domain, 3), 0xaa) }},
		{"unaccounted authority record", func() []byte { b := dnsReplyFixture(domain, 3); binary.BigEndian.PutUint16(b[8:10], 1); return b }},
		{"truncated authority RR header", func() []byte {
			b := dnsReplyFixture(domain, 3, []byte{0})
			binary.BigEndian.PutUint16(b[8:10], 1)
			return b
		}},
		{"truncated authority RR data", func() []byte {
			rr := dnsTestRR([]byte{0}, 6, 0, nil)
			binary.BigEndian.PutUint16(rr[9:11], 4)
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[8:10], 1)
			return b
		}},
		{"extended RCODE 19", func() []byte {
			rr := dnsTestRR([]byte{0}, 41, 1<<24, nil)
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[10:12], 1)
			return b
		}},
		{"unsupported EDNS version", func() []byte {
			rr := dnsTestRR([]byte{0}, 41, 1<<16, nil)
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[10:12], 1)
			return b
		}},
		{"truncated EDNS option header", func() []byte {
			rr := dnsTestRR([]byte{0}, 41, 0, []byte{0, 1})
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[10:12], 1)
			return b
		}},
		{"truncated EDNS option data", func() []byte {
			rr := dnsTestRR([]byte{0}, 41, 0, []byte{0, 1, 0, 4, 0})
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[10:12], 1)
			return b
		}},
		{"duplicate OPT", func() []byte {
			b := dnsReplyFixture(domain, 3, opt, opt)
			binary.BigEndian.PutUint16(b[10:12], 2)
			return b
		}},
		{"OPT in authority", func() []byte { b := dnsReplyFixture(domain, 3, opt); binary.BigEndian.PutUint16(b[8:10], 1); return b }},
		{"OPT owner not root", func() []byte {
			rr := dnsTestRR([]byte{0xc0, 0x0c}, 41, 0, nil)
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[10:12], 1)
			return b
		}},
		{"compression pointer into header", func() []byte {
			rr := dnsTestRR([]byte{0xc0, 0x00}, 6, 0, nil)
			b := dnsReplyFixture(domain, 3, rr)
			binary.BigEndian.PutUint16(b[8:10], 1)
			return b
		}},
		{"bogus count", func() []byte { b := dnsReplyFixture(domain, 3); binary.BigEndian.PutUint16(b[10:12], 65535); return b }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if rcode, _, err := dmarcDNSRCODE(tc.reply(), 0x5a5a, domain); err == nil {
				t.Fatalf("invalid DNS negative response accepted as RCODE %d", rcode)
			}
		})
	}
}

func TestDMARCDNSMalformedExtendedRCODEIsNotActionableOverUDP(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		reply := append([]byte(nil), buffer[:n]...)
		binary.BigEndian.PutUint16(reply[2:4], 0x8183)
		binary.BigEndian.PutUint16(reply[10:12], 1)
		reply = append(reply, dnsTestRR([]byte{0}, 41, 1<<24, nil)...)
		_, err = conn.WriteTo(reply, addr)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	nx, err := (dmarcDNSClient{serversOverride: []string{conn.LocalAddr().String()}}).nameNXDOMAIN(ctx, "sender.example.org")
	if err == nil || nx {
		t.Fatalf("extended RCODE became actionable: nx=%v err=%v", nx, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
