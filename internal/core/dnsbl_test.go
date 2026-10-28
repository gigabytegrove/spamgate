package core

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type dnsblStub struct {
	ips    []net.IPAddr
	err    error
	called string
}

func (s *dnsblStub) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (s *dnsblStub) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (s *dnsblStub) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	s.called = name
	return s.ips, s.err
}
func TestDNSBLResultValidation(t *testing.T) {
	cases := []struct {
		name   string
		ips    []string
		err    error
		listed bool
	}{
		{"valid 127 result", []string{"127.0.0.2"}, nil, true},
		{"wildcard public answer", []string{"192.0.2.1"}, nil, false},
		{"IPv6 answer", []string{"::1"}, nil, false},
		{"not found", nil, &net.DNSError{IsNotFound: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &dnsblStub{err: tc.err}
			for _, ip := range tc.ips {
				res.ips = append(res.ips, net.IPAddr{IP: net.ParseIP(ip)})
			}
			detail, hit, err := dnsblLookup(context.Background(), res, "198.51.100.23", "rbl.example.org")
			if err != nil || hit != tc.listed || res.called != "23.100.51.198.rbl.example.org" || !strings.Contains(detail, res.called) {
				t.Fatalf("detail %q hit %t err %v query %q", detail, hit, err, res.called)
			}
		})
	}
	for _, bad := range []string{"127.0.0.1", "10.0.0.1", "::1", "not-an-ip"} {
		stub := &dnsblStub{err: errors.New("should not be called")}
		_, hit, err := dnsblLookup(context.Background(), stub, bad, "rbl.example.org")
		if hit || err != nil || stub.called != "" {
			t.Fatalf("bad ip %s queried DNS", bad)
		}
	}
}
