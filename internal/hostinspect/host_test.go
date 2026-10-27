package hostinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendMilter(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"", LocalMilter},
		{LocalMilter, LocalMilter},
		{"inet:127.0.0.1:9999", "inet:127.0.0.1:9999, " + LocalMilter},
		{"inet:a:2, " + LocalMilter, "inet:a:2, " + LocalMilter},
	} {
		if got := AppendMilter(tc.in); got != tc.out {
			t.Errorf("%q => %q, expected %q", tc.in, got, tc.out)
		}
	}
}
func TestDetectPanelAndExistingMilter(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"etc/postfix/main.cf", "usr/local/ispconfig/server"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}
	probe := Probe{Root: root,
		Lookup: func(s string) (string, error) {
			if s == "postconf" {
				return "/usr/sbin/postconf", nil
			}
			return "", errors.New("missing")
		},
		Run: func(_ context.Context, _ string, args ...string) (string, error) {
			if strings.Join(args, " ") != "-h smtpd_milters" {
				t.Fatal(args)
			}
			return "inet:127.0.0.1:11332", nil
		},
		Reach: func(string) bool { return true },
	}
	r := probe.Detect(context.Background())
	if r.Panel != "ispconfig" || r.MailServer != "postfix" || !r.MilterReady || r.ProposedMilters != "inet:127.0.0.1:11332, "+LocalMilter {
		t.Fatalf("bad report: %+v", r)
	}
	if len(r.Notes) == 0 || !strings.Contains(strings.Join(r.Notes, " "), "automatic Postfix changes are disabled") {
		t.Fatal(r.Notes)
	}
}
func TestDetectCpanelExim(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/cpanel"), 0755); err != nil {
		t.Fatal(err)
	}
	p := Probe{Root: root, Lookup: func(s string) (string, error) {
		if s == "exim" {
			return "/usr/sbin/exim", nil
		}
		return "", errors.New("no")
	}, Reach: func(string) bool { return false }}
	r := p.Detect(context.Background())
	if r.Panel != "cpanel" || r.MailServer != "exim" || r.Integration != "exim-adapter-pending" {
		t.Fatalf("bad report: %+v", r)
	}
}
func TestDetectMissingPostconfDoesNotAssumeBlank(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/local/ispconfig/server"), 0755); err != nil {
		t.Fatal(err)
	}
	p := Probe{Root: root, Lookup: func(s string) (string, error) {
		if s == "postconf" {
			return "postconf", nil
		}
		return "", errors.New("not found")
	}, Run: func(context.Context, string, ...string) (string, error) { return "", errors.New("denied") }, Reach: func(string) bool { return false }}
	r := p.Detect(context.Background())
	if r.ProposedMilters != "" {
		t.Fatalf("unsafe default: %+v", r)
	}
}

func TestCpanelPrefersManagedEximOverStrayPostfix(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"var/cpanel", "etc/postfix"} {
		if err := os.MkdirAll(filepath.Join(root, rel), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/postfix/main.cf"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	p := Probe{Root: root, Lookup: func(string) (string, error) { return "found", nil }, Reach: func(string) bool { return false }}
	r := p.Detect(context.Background())
	if r.Panel != "cpanel" || r.MailServer != "exim" {
		t.Fatalf("cPanel MTA overridden by stray Postfix: %+v", r)
	}
}
