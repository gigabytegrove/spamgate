// Package hostinspect provides a read-only inventory of a native mail-server
// installation. It never rewrites Postfix, Exim or hosting-panel configuration.
package hostinspect

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const LocalMilter = "inet:127.0.0.1:38472"

type Report struct {
	Platform        string   `json:"platform"`
	Panel           string   `json:"panel"`
	MailServer      string   `json:"mail_server"`
	Integration     string   `json:"integration"`
	ExistingMilters string   `json:"existing_milters,omitempty"`
	ProposedMilters string   `json:"proposed_milters,omitempty"`
	MilterReady     bool     `json:"milter_ready"`
	Notes           []string `json:"notes"`
}

type Probe struct {
	Root   string
	Lookup func(string) (string, error)
	Run    func(context.Context, string, ...string) (string, error)
	Reach  func(string) bool
}

func realRun(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	return strings.TrimSpace(string(output)), err
}
func realReach(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 350*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Detect inspects the current host. Missing tools and inaccessible paths are
// classified as unknown instead of being interpreted as a clean installation.
func Detect(ctx context.Context) Report { return Probe{}.Detect(ctx) }
func (p Probe) Detect(ctx context.Context) Report {
	root := p.Root
	if root == "" {
		root = "/"
	}
	lookup := p.Lookup
	if lookup == nil {
		lookup = exec.LookPath
	}
	run := p.Run
	if run == nil {
		run = realRun
	}
	reach := p.Reach
	if reach == nil {
		reach = realReach
	}
	exists := func(name string) bool {
		full := filepath.Join(root, strings.TrimPrefix(filepath.Clean(name), "/"))
		_, err := os.Stat(full)
		return err == nil
	}
	result := Report{Platform: runtime.GOOS, Panel: "none", MailServer: "unknown", Integration: "manual", Notes: []string{}}
	if runtime.GOOS != "linux" && p.Root == "" {
		result.Notes = append(result.Notes, "Native Linux mail-server inspection is available only on Linux.")
		return result
	}
	switch {
	case exists("/usr/local/cpanel/cpanel") || exists("/var/cpanel"):
		result.Panel = "cpanel"
	case exists("/usr/local/ispconfig/server") || exists("/usr/local/ispconfig/interface"):
		result.Panel = "ispconfig"
	case exists("/usr/local/psa"):
		result.Panel = "plesk"
	case exists("/usr/local/directadmin"):
		result.Panel = "directadmin"
	}
	postfixPath, postfixErr := lookup("postconf")
	_, eximErr := lookup("exim")
	if result.Panel == "cpanel" && eximErr == nil {
		result.MailServer = "exim"
	} else if postfixErr == nil && (exists("/etc/postfix/main.cf") || result.Panel == "ispconfig") {
		result.MailServer = "postfix"
	} else if eximErr == nil && (exists("/etc/exim.conf") || result.Panel == "cpanel") {
		result.MailServer = "exim"
	}
	result.MilterReady = reach("127.0.0.1:38472")
	if result.MailServer == "postfix" {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		current, err := run(c, postfixPath, "-h", "smtpd_milters")
		cancel()
		if err != nil {
			result.Notes = append(result.Notes, "Unable to read Postfix milter configuration; do not assume it is empty.")
		}
		if err == nil {
			result.ExistingMilters = current
			result.ProposedMilters = AppendMilter(current)
		}
		result.Integration = "postfix-milter"
		if result.Panel != "none" {
			result.Notes = append(result.Notes, "Hosting panel detected: use its supported persistence/integration method; automatic Postfix changes are disabled.")
		} else if strings.TrimSpace(current) != "" && !strings.Contains(current, LocalMilter) {
			result.Notes = append(result.Notes, "Existing milters detected. Review order, reject behavior and duplicate scanning before integrating.")
		}
		if !result.MilterReady {
			result.Notes = append(result.Notes, "SpamGate local Milter is not answering on 127.0.0.1:38472. Enable it before configuring Postfix.")
		}
	} else if result.MailServer == "exim" {
		result.Integration = "exim-adapter-pending"
		result.Notes = append(result.Notes, "No certified Exim ACL/spamd adapter is installed. Do not change Exim delivery settings yet.")
		if result.Panel == "cpanel" {
			result.Notes = append(result.Notes, "Use WHM > Service Configuration > Exim Configuration Manager; direct edits to /etc/exim.conf will be overwritten.")
		}
	} else {
		result.Notes = append(result.Notes, "Could not identify a supported local MTA. Use the documented HTTP scan API with an adapter that enforces verdicts.")
	}
	if result.Panel == "none" && result.MailServer == "unknown" && postfixErr == nil && eximErr == nil {
		result.Notes = append(result.Notes, "Multiple mail binaries found; verify which MTA handles live traffic.")
	}
	return result
}

func AppendMilter(existing string) string {
	existing = strings.TrimSpace(existing)
	for _, part := range strings.FieldsFunc(existing, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if part == LocalMilter {
			return existing
		}
	}
	if existing == "" {
		return LocalMilter
	}
	return existing + ", " + LocalMilter
}

// Ensure Probe values are only used for diagnostics, never to imply an active
// enforcement route. This sentinel is kept for callers requiring explicit
// unsupported-environment errors when adding future adapters.
var ErrUnsupported = errors.New("mail integration not supported on this host")
