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
	Platform               string   `json:"platform"`
	Panel                  string   `json:"panel"`
	MailServer             string   `json:"mail_server"`
	Integration            string   `json:"integration"`
	ExistingMilters        string   `json:"existing_milters,omitempty"`
	NonSMTPDMilters        string   `json:"non_smtpd_milters,omitempty"`
	MilterDefaultAction    string   `json:"milter_default_action,omitempty"`
	MilterProtocol         string   `json:"milter_protocol,omitempty"`
	PostfixSmtpdMilterMaps string   `json:"postfix_smtpd_milter_maps,omitempty"`
	PostfixConfigured      bool     `json:"postfix_configured"`
	PostfixCoverageUncertain bool `json:"postfix_coverage_uncertain"`
	PostfixServiceMilterOverrides []string `json:"postfix_service_milter_overrides,omitempty"`
	PostfixServiceOverrideInventoryTruncated bool `json:"postfix_service_override_inventory_truncated"`
	ProposedMilters        string   `json:"proposed_milters,omitempty"`
	MilterReady            bool     `json:"milter_ready"`
	Notes                  []string `json:"notes"`
}

type Probe struct {
	Root   string
	Lookup func(string) (string, error)
	Run    func(context.Context, string, ...string) (string, error)
	Reach  func(string) bool
	// MasterOverrides reads Postfix master.cf service parameter overrides.
	MasterOverrides func(context.Context) (string, error)
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
			result.PostfixCoverageUncertain = true
			result.Notes = append(result.Notes, "Unable to read Postfix milter configuration; do not assume it is empty.")
		}
		if err == nil {
			result.ExistingMilters = current
			result.ProposedMilters = AppendMilter(current)
		}
		// Inspect both Postfix paths. A correct global smtpd_milters value
		// is not proof of non-SMTP coverage; local submission uses another key.
		readPostconf := func(key string) string {
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			value, e := run(c, postfixPath, "-h", key)
			if e != nil {
				result.PostfixCoverageUncertain = true
				result.Notes = append(result.Notes, "Could not inspect Postfix "+key+"; verify it manually.")
				return ""
			}
			return strings.TrimSpace(value)
		}
		result.NonSMTPDMilters = readPostconf("non_smtpd_milters")
		result.MilterProtocol = readPostconf("milter_protocol")
		result.MilterDefaultAction = readPostconf("milter_default_action")
		result.PostfixSmtpdMilterMaps = readPostconf("smtpd_milter_maps")
		// postconf -h reads main.cf only. master.cf -o overrides can bypass
		// those global values for submission and other SMTP services.
		// Custom probes may inject this inspection without executing binaries.
		if p.Run != nil && p.MasterOverrides == nil {
			// A custom command runner may not implement postconf -P. Do not
			// silently treat an uninspected master.cf as proof of coverage.
			result.PostfixCoverageUncertain = true
			result.Notes = append(result.Notes, "Postfix master.cf service overrides were not inspected; SMTP service coverage is unverified.")
		} else {
			inspect := p.MasterOverrides
			if inspect == nil {
				inspect = func(c context.Context) (string, error) { return run(c, postfixPath, "-P") }
			}
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			overrides, inspectErr := inspect(c)
			cancel()
			if inspectErr != nil {
				result.PostfixCoverageUncertain = true
				result.Notes = append(result.Notes, "Could not inspect Postfix master.cf service overrides; SMTP service coverage is unverified.")
			} else {
				entries, truncated := InspectMilterServiceOverrides(overrides)
				result.PostfixServiceMilterOverrides = entries
				result.PostfixServiceOverrideInventoryTruncated = truncated
				if len(entries) > 0 {
					result.PostfixCoverageUncertain = true
					result.Notes = append(result.Notes, "Postfix master.cf contains service-specific Milter overrides; verify each SMTP service and submission path independently.")
				}
				if truncated {
					result.PostfixCoverageUncertain = true
					result.Notes = append(result.Notes, "Postfix master.cf Milter override inventory is incomplete; review the full service configuration before trusting coverage.")
				}
			}
		}

		result.PostfixConfigured = ContainsLocalMilter(result.ExistingMilters) && ContainsLocalMilter(result.NonSMTPDMilters)
		if !result.PostfixConfigured || !result.MilterReady {
			result.PostfixCoverageUncertain = true
		}
		if hasWrongSpamGatePort(result.ExistingMilters) || hasWrongSpamGatePort(result.NonSMTPDMilters) {
			result.Notes = append(result.Notes, "WRONG PORT: 38471 is SpamGate HTTP scanning, not Milter. Postfix needs inet:127.0.0.1:38472.")
		}
		if !result.PostfixConfigured {
			result.Notes = append(result.Notes, "Postfix is not configured to use SpamGate Milter on both smtpd_milters and non_smtpd_milters. Mail can bypass SpamGate.")
		}
		if result.MilterDefaultAction != "tempfail" && result.MilterDefaultAction != "reject" {
			result.PostfixCoverageUncertain = true
			result.Notes = append(result.Notes, "Postfix Milter failure behavior is not confirmed fail-closed (tempfail/reject); verify milter_default_action before relying on enforcement.")
		}
		if result.MilterDefaultAction == "accept" {
			result.PostfixCoverageUncertain = true
			result.Notes = append(result.Notes, "Postfix is set to accept mail when the Milter fails; scanning can be bypassed silently. Use tempfail after verifying connectivity, understanding it defers mail during outages.")
		}
		if result.MilterProtocol == "" {
			result.PostfixCoverageUncertain = true
			result.Notes = append(result.Notes, "Postfix Milter protocol could not be confirmed; verify compatibility with SpamGate.")
		}
		if result.PostfixSmtpdMilterMaps != "" {
			result.PostfixCoverageUncertain = true
			result.Notes = append(result.Notes, "Postfix smtpd_milter_maps may override/disable the Milter for some SMTP clients; inspect those rules.")
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

// ContainsLocalMilter checks for the exact loopback listener SpamGate advertises.
// Do not treat the HTTP scanner's 38471 port as a Milter endpoint.
func ContainsLocalMilter(existing string) bool {
	for _, part := range strings.FieldsFunc(existing, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if part == LocalMilter || part == "inet:localhost:38472" {
			return true
		}
	}
	return false
}
func hasWrongSpamGatePort(existing string) bool {
	for _, part := range strings.FieldsFunc(existing, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if part == "inet:localhost:38471" || part == "inet:127.0.0.1:38471" {
			return true
		}
	}
	return false
}

func AppendMilter(existing string) string {
	existing = strings.TrimSpace(existing)
	for _, part := range strings.FieldsFunc(existing, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if part == LocalMilter || part == "inet:localhost:38472" {
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

// ListMilterServiceOverrides returns service/transport/parameter identities,
// never configuration values (which may contain local paths or credentials).
// The result is bounded to avoid exposing unbounded command output in the UI.
// InspectMilterServiceOverrides returns at most 64 safe parameter identities.
// The second result is true when inspection discarded any candidate because
// the inventory limit or identity length was exceeded. A truncated inventory
// must never be interpreted as complete Milter enforcement coverage.
func InspectMilterServiceOverrides(output string) ([]string, bool) {
	const maxEntries = 64
	const maxIdentityBytes = 512
	const maxOutputBytes = 1 << 20
	var found []string
	seen := make(map[string]bool)
	truncated := false

	// postconf -P output is untrusted host configuration. Never split an
	// arbitrarily large response into a second, potentially huge allocation.
	// A partial inventory must explicitly invalidate coverage confidence.
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes]
		truncated = true
	}
	for len(output) > 0 {
		line, rest, hasNext := strings.Cut(output, "\n")
		if hasNext {
			output = rest
		} else {
			output = ""
		}
		// A huge malformed line is not safe to publish as an identity.
		if len(line) > maxIdentityBytes+256 {
			if strings.Contains(line, "milter") {
				truncated = true
			}
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			// A malformed service assignment cannot establish coverage.
			if strings.Contains(line, "milter") {
				truncated = true
			}
			continue
		}
		key = strings.TrimSpace(key)
		parts := strings.Split(key, "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
			if strings.Contains(key, "milter") {
				truncated = true
			}
			continue
		}
		switch parts[2] {
		case "smtpd_milters", "non_smtpd_milters", "milter_default_action", "milter_protocol", "smtpd_milter_maps":
			if len(key) > maxIdentityBytes {
				truncated = true
				continue
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(found) == maxEntries {
				truncated = true
				continue
			}
			found = append(found, key)
		}
	}
	return found, truncated
}

// ListMilterServiceOverrides preserves the bounded legacy inventory API.
func ListMilterServiceOverrides(output string) []string {
	entries, _ := InspectMilterServiceOverrides(output)
	return entries
}

// HasMilterServiceOverrides reports whether any service-specific Milter
// setting exists, including overrides which happen to match global values.
func HasMilterServiceOverrides(output string) bool {
	return len(ListMilterServiceOverrides(output)) != 0
}
