package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Input struct {
	Raw        []byte
	Sender     string
	Recipients []string
	ClientIP   string
	Helo       string
	Connector  string
}
type Scanner struct {
	Store    *Store
	Resolver SPFResolver
}

var urlPattern = regexp.MustCompile(`(?i)https?://[^\s<>"'()]+`)
var htmlTag = regexp.MustCompile(`(?s)<[^>]*>`)
var suspiciousWords = []struct {
	word   string
	weight float64
}{
	{"verify your account", 2.5}, {"confirm your password", 3.5}, {"act immediately", 1.5},
	{"account suspended", 2.0}, {"wire transfer", 1.5}, {"gift card", 1.5}, {"crypto wallet", 1.5},
	{"click here to avoid", 2.5}, {"unusual sign-in", 1.0}, {"security alert", 0.5},
}

func decodedHeader(s string) string {
	d := new(mime.WordDecoder)
	x, e := d.DecodeHeader(s)
	if e == nil {
		return x
	}
	return s
}
// mimeCoverage is a bounded, content-free record of gaps in the ordinary
// text, URL and attachment-filename extraction path. It does not make a
// disposition decision; incomplete inspection must be visible to operators.
type mimeCoverage struct {
	Parts int
	Incomplete bool
	Reasons []string
}
func (c *mimeCoverage) mark(reason string) {
	if c == nil { return }
	c.Incomplete = true
	for _, existing := range c.Reasons {
		if existing == reason { return }
	}
	if len(c.Reasons) < 6 { c.Reasons = append(c.Reasons, reason) }
}

// Preserve the existing helper API for callers that need extracted content
// without the coverage report. Both paths use the same shared part budget.
func bodyParts(h mail.Header, body []byte, depth int) (string, []string, []string, bool) {
	return bodyPartsWithCoverage(h, body, depth, &mimeCoverage{})
}
func bodyPartsWithCoverage(h mail.Header, body []byte, depth int, coverage *mimeCoverage) (string, []string, []string, bool) {
	if depth > 8 {
		coverage.mark("MIME nesting exceeds 8 levels")
		return "", nil, nil, false
	}
	contentType := h.Get("Content-Type")
	media, params, e := mime.ParseMediaType(contentType)
	if e != nil {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "multipart/") {
			coverage.mark("Malformed multipart Content-Type")
			return "", nil, nil, false
		}
		media = "text/plain"
	}
	if strings.HasPrefix(media, "multipart/") {
		if params["boundary"] == "" {
			coverage.mark("Multipart boundary missing")
			return "", nil, nil, false
		}
		// Keep transfer encoding intact: NextPart's permissive quoted-printable
		// decoder can conceal malformed escapes before our strict validator.
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		var all strings.Builder
		var attachments, urls []string
		hasHTML := false
		for {
			// A single shared budget across nested multiparts prevents a
			// malicious tree of 75 children per level from bypassing limits.
			if coverage.Parts >= 75 {
				part, nextErr := reader.NextRawPart()
				if nextErr == nil {
					_ = part.Close()
					coverage.mark("More than 75 MIME parts; remainder not scanned")
				} else if nextErr != io.EOF {
					coverage.mark("Multipart termination could not be parsed")
				}
				break
			}
			part, nextErr := reader.NextRawPart()
			if nextErr == io.EOF { break }
			if nextErr != nil {
				coverage.mark("Multipart section could not be parsed")
				break
			}
			coverage.Parts++
			// Read one byte beyond the limit so an oversized part is never
			// silently mistaken for a complete, inspected MIME section.
			p, readErr := io.ReadAll(io.LimitReader(part, (5<<20)+1))
			_ = part.Close()
			if readErr != nil {
				coverage.mark("MIME part could not be read")
				continue
			}
			if len(p) > 5<<20 {
				coverage.mark("MIME part exceeds 5 MiB extraction limit")
				continue
			}
			text, a, u, html := bodyPartsWithCoverage(mail.Header(part.Header), p, depth+1, coverage)
			all.WriteString(text)
			all.WriteByte(' ')
			attachments = append(attachments, a...)
			urls = append(urls, u...)
			hasHTML = hasHTML || html
		}
		return all.String(), attachments, urls, hasHTML
	}
	name := params["name"]
	if disposition, ps, e := mime.ParseMediaType(h.Get("Content-Disposition")); e == nil {
		if ps["filename"] != "" { name = ps["filename"] }
		if disposition == "attachment" && name == "" { name = "unnamed attachment" }
	}
	if name != "" { return "", []string{name}, nil, false }
	if media != "text/plain" && media != "text/html" { return "", nil, nil, false }
	decoded, transferErr := decodeMIMETextTransfer(body, h.Get("Content-Transfer-Encoding"))
	if transferErr != nil {
		coverage.mark(transferErr.Error())
		return "", nil, nil, media == "text/html"
	}
	if len(decoded) > 2<<20 {
		coverage.mark("Decoded text exceeds 2 MiB extraction limit")
		decoded = decoded[:2<<20]
	}
	text := string(decoded)
	matches := urlPattern.FindAllString(text, 101)
	if len(matches) > 100 {
		coverage.mark("More than 100 URLs; remaining links not inspected")
		matches = matches[:100]
	}
	if media == "text/html" { text = htmlTag.ReplaceAllString(text, " ") }
	return text, nil, matches, media == "text/html"
}
func decodeBase64(b []byte) []byte {
	var clean bytes.Buffer
	for _, c := range b {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			clean.WriteByte(c)
		}
	}
	raw := clean.Bytes()
	if len(raw) == 0 {
		return nil
	}
	d := make([]byte, len(raw))
	n, e := base64Decode(d, raw)
	if e != nil {
		return b
	}
	return d[:n]
}
func decodeQP(b []byte) []byte {
	r := quotedPrintableReader(bytes.NewReader(b))
	out, e := io.ReadAll(io.LimitReader(r, 2<<20))
	if e != nil {
		return b
	}
	return out
}

// ErrInvalidMessage marks a permanently malformed RFC 5322 original.
// Infrastructure failures must remain retryable SMTP 451 responses.
var ErrInvalidMessage = errors.New("invalid RFC 5322 message")

// Decoding functions are in codec.go to isolate MIME transfer handling.
func (s *Scanner) Scan(ctx context.Context, in Input) (out Message, scanErr error) {
	started := time.Now()
	defer func() {
        observeScan(in.Connector, out.Action, time.Since(started), scanErr != nil)
        if scanErr == nil { observeDetectionFindings(out.Findings) }
    }()
	if len(in.Raw) == 0 || len(in.Raw) > 10<<20 {
		return Message{}, fmt.Errorf("%w: size must be 1–10485760 bytes", ErrInvalidMessage)
	}
	cfg := s.Store.Config()
	selected := SelectRecipientThresholds(cfg.Settings, cfg.RecipientPolicies, in.Recipients)
	cfg.Settings.TagThreshold = selected.TagThreshold
	cfg.Settings.QuarantineThreshold = selected.QuarantineThreshold
	cfg.Settings.RejectThreshold = selected.RejectThreshold
	policyDetail := selected.Detail
	trace := &ScoringTrace{TagThreshold: cfg.Settings.TagThreshold, QuarantineThreshold: cfg.Settings.QuarantineThreshold, RejectThreshold: cfg.Settings.RejectThreshold}
	note := func(name, status, detail string) {
		trace.Checks = append(trace.Checks, ScanCheck{Name: name, Status: status, Detail: detail})
	}
	note("Policy selection", "info", policyDetail)
	m := Message{ID: ID(), Timestamp: time.Now().UTC(), Sender: strings.TrimSpace(in.Sender), Recipients: append([]string(nil), in.Recipients...), ClientIP: in.ClientIP, Connector: in.Connector, Size: len(in.Raw), Action: "accept"}
	parsed, e := mail.ReadMessage(bytes.NewReader(in.Raw))
	if e != nil {
		return Message{}, fmt.Errorf("%w: %v", ErrInvalidMessage, e)
	}
	m.HeaderSnapshot, m.HeaderTruncated = CaptureHeaders(in.Raw)
	m.MessageID = parsed.Header.Get("Message-Id")
	m.Subject = decodedHeader(parsed.Header.Get("Subject"))
	// Preserve the SMTP/Milter null reverse path. A bounce with MAIL FROM:<> must
	// never inherit the RFC 5322 From identity, or the delivery worker can
	// generate a new bounce instead of forwarding the original DSN envelope.
	// Ad-hoc scans without a transport connector retain the historical display fallback.
	if m.Sender == "" && in.Connector == "" {
		m.Sender = parsed.Header.Get("From")
	}
	body, e := io.ReadAll(io.LimitReader(parsed.Body, 10<<20))
	if e != nil {
		return Message{}, e
	}
	coverage := &mimeCoverage{}
	text, attachments, urls, hasHTML := bodyPartsWithCoverage(parsed.Header, body, 0, coverage)
	var findings []Finding
	matchedSince := func(n int) string {
		if len(findings) > n {
			return "match"
		}
		return "clear"
	}
	add := func(symbol, source, detail string, weight float64) {
		if strings.HasPrefix(source, "builtin/") || strings.HasPrefix(source, "auth/") || strings.HasPrefix(source, "antivirus/") || strings.HasPrefix(source, "learning/") || strings.HasPrefix(source, "external/") {
			if p, ok := cfg.SignalPolicies[symbol]; ok {
				if !p.Enabled {
					return
				}
				weight = p.Score
			}
		}
		findings = append(findings, Finding{symbol, source, detail, weight})
	}
	// Report extraction blind spots as zero-score diagnostic evidence. A
	// missing/oversized section is not by itself proof of spam and must not
	// silently change a production SMTP action.
	if coverage.Incomplete {
		detail := strings.Join(coverage.Reasons, "; ")
		findings = append(findings, Finding{Symbol: "MIME_COVERAGE_INCOMPLETE", Source: "diagnostic/mime", Detail: detail, Score: 0})
		note("MIME text and filename coverage", "error", detail)
	} else {
		note("MIME text and filename coverage", "clear", fmt.Sprintf("Inspected %d MIME part(s) within extraction limits", coverage.Parts))
	}
	builtinStart := len(findings)
	if parsed.Header.Get("From") == "" {
		add("MISSING_FROM", "builtin/header", "From header absent", 2)
	}
	if parsed.Header.Get("Date") == "" {
		add("MISSING_DATE", "builtin/header", "Date header absent", 0.5)
	}
	if len(m.Recipients) == 0 {
		add("UNKNOWN_RECIPIENT", "builtin/envelope", "No recipient metadata supplied", 0.5)
	}
	if parsed.Header.Get("Message-Id") == "" {
		add("MISSING_MESSAGE_ID", "builtin/header", "Message-ID header absent", 1)
	}
	if hasHTML && strings.TrimSpace(text) == "" {
		add("EMPTY_HTML", "builtin/mime", "HTML without usable text", 0.5)
	}
	note("Message headers", matchedSince(builtinStart), "Checked From, Date, Message-ID and recipient metadata")
	contentStart := len(findings)
	lower := strings.ToLower(m.Subject + " " + text)
	for _, rule := range suspiciousWords {
		if strings.Contains(lower, rule.word) {
			add("CONTENT_"+strings.ToUpper(strings.ReplaceAll(rule.word, " ", "_")), "builtin/content", rule.word, rule.weight)
		}
	}
	note("Suspicious wording", matchedSince(contentStart), "Compared subject and decoded text with the built-in phrase rules")
	// Synthetic SGTUBE patterns may affect only an explicitly configured, single
	// envelope-recipient test mailbox or a privileged in-memory laboratory scan.
	testID := ""
	if in.Connector == "test-lab" || TestRecipientAllowed(in.Recipients) {
		testID = DetectCategoryTest(text)
		if testID != "" {
			add("SGTUBE_"+strings.ToUpper(testID), "test/sgtube", "Synthetic category test: "+testID+"; does not prove detection of a real threat", cfg.Settings.RejectThreshold+1)
			note("SGTUBE synthetic category test", "match", "Administrator lab or single allowlisted test mailbox")
		}
	}
	if cfg.Settings.AttachmentInspection {
		initial := len(findings)
		detected, inspectionErr := InspectMIMEAttachments(in.Raw)
		if inspectionErr != nil {
			note("Attachment contents", "error", inspectionErr.Error())
		} else {
			totalWeight := 0.0
			for _, f := range detected {
				weight := f.Score
				if totalWeight+weight > 10 {
					weight = 10 - totalWeight
				}
				if weight < 0 {
					weight = 0
				}
				totalWeight += weight
				add(f.Symbol, "builtin/mime-content", f.Detail, weight)
			}
			note("Attachment contents", matchedSince(initial), fmt.Sprintf("Examined MIME parts, executable signatures and ZIP metadata; %d finding(s); penalty capped at +10. Does not replace ClamAV", len(detected)))
		}
	} else {
		note("Attachment contents", "skipped", "Optional bounded content and ZIP inspection disabled")
	}
	attachmentStart := len(findings)
	for _, filename := range attachments {
		for _, risk := range attachmentNameFindings(filename) {
			switch risk.Symbol {
			case "ATTACHMENT_RISKY_EXTENSION":
				// Preserve existing policy symbol and its executable weight.
				// Macro-enabled Office filenames alone receive a lower weight.
				weight := 5.0
				if risk.Score < weight { weight = risk.Score }
				add("RISKY_ATTACHMENT", "builtin/attachment", attachmentLabel(filename), weight)
			case "ATTACHMENT_DOUBLE_EXTENSION":
				add("DOUBLE_EXTENSION", "builtin/attachment", attachmentLabel(filename), 4)
			default:
				add(risk.Symbol, "builtin/attachment", risk.Detail, risk.Score)
			}
		}
	}
	note("Attachment filenames", matchedSince(attachmentStart), fmt.Sprintf("Checked %d attachment filename(s) for risky extensions; this is not a full attachment-content scan", len(attachments)))
	urlStart := len(findings)
	domains := map[string]bool{}
	for _, rawURL := range urls {
		u, e := url.Parse(strings.TrimRight(rawURL, ".,;"))
		if e != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}
		domains[host] = true
		if net.ParseIP(host) != nil {
			add("IP_URL", "builtin/url", host, 2.5)
		}
		if strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--") {
			add("PUNYCODE_URL", "builtin/url", host, 1.5)
		}
		if len(host) > 120 {
			add("LONG_HOSTNAME", "builtin/url", host, 1)
		}
	}
	if len(domains) > 8 {
		add("MANY_LINK_DOMAINS", "builtin/url", fmt.Sprintf("%d unique domains", len(domains)), 2)
	}
	note("Links", matchedSince(urlStart), fmt.Sprintf("Inspected %d extracted link(s) for suspicious URL patterns", len(urls)))
	if cfg.Settings.PhishingLinks {
		phishStart := len(findings)
		phish, phishingCoverage := detectPhishingLinksWithCoverage(in.Raw)
		for _, item := range phish {
			add("PHISHING_VISIBLE_LINK", "builtin/phishing", item, 3)
		}
		if phishingCoverage.Incomplete {
			detail := strings.Join(phishingCoverage.Reasons, "; ")
			findings = append(findings, Finding{Symbol: "PHISHING_COVERAGE_INCOMPLETE", Source: "diagnostic/phishing", Detail: detail, Score: 0})
			note("Visible-link impersonation", "error", detail)
		} else {
			note("Visible-link impersonation", matchedSince(phishStart), fmt.Sprintf("Compared link display text to actual destinations; %d mismatches", len(phish)))
		}
	} else {
		note("Visible-link impersonation", "skipped", "Opt-in phishing link inspection is disabled")
	}
	// Rules are evaluated after built-ins and retain provenance and their configured weight.
	forced := ""
	senderDomain := strings.ToLower(strings.TrimSpace(m.Sender))
	if p := strings.LastIndex(senderDomain, "@"); p >= 0 {
		senderDomain = senderDomain[p+1:]
	}
	rulesStart := len(findings)
	eligibleRules := 0
	mixedRecipientRuleSkips := 0
	rules := append([]Rule(nil), cfg.Rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	for _, rule := range rules {
		if !rule.Enabled || (!rule.ExpiresAt.IsZero() && !time.Now().Before(rule.ExpiresAt)) || strings.TrimSpace(rule.Value) == "" {
			continue
		}
		eligibleRules++
		if rule.Owner != "" {
			if len(m.Recipients) == 0 {
				continue
			}
			all := true
			for _, recipient := range m.Recipients {
				if !equalEmail(recipient, rule.Owner) {
					all = false
					break
				}
			}
			if !all {
				continue
			}
		}
		val := strings.ToLower(rule.Value)
		matched := false
		switch rule.Kind {
		case "sender_email":
			matched = strings.EqualFold(m.Sender, rule.Value)
		case "sender_domain":
			matched = senderDomain == val || strings.HasSuffix(senderDomain, "."+val)
		case "recipient_email":
			// The Milter returns one disposition for the entire SMTP
			// transaction. A rule targeting one mailbox must not reject,
			// quarantine, accept or score unrelated co-recipients.
			// A recipient-specific rule applies only if EVERY envelope
			// recipient matches the same mailbox (duplicates are safe).
			matched = len(m.Recipients) > 0
			anyTargeted := false
			for _, r := range m.Recipients {
				if equalEmail(r, rule.Value) {
					anyTargeted = true
				} else {
					matched = false
				}
			}
			if anyTargeted && !matched {
				mixedRecipientRuleSkips++
			}
		case "client_ip":
			matched = m.ClientIP == rule.Value
		case "subject_contains":
			matched = strings.Contains(strings.ToLower(m.Subject), val)
		case "body_contains":
			matched = strings.Contains(strings.ToLower(text), val)
		case "url_domain":
			for d := range domains {
				if d == val || strings.HasSuffix(d, "."+val) {
					matched = true
				}
			}
		case "header_contains":
			end := bytes.Index(in.Raw, []byte("\r\n\r\n"))
			if end < 0 {
				end = bytes.Index(in.Raw, []byte("\n\n"))
			}
			if end < 0 {
				end = len(in.Raw)
			}
			matched = strings.Contains(strings.ToLower(string(in.Raw[:minInt(end, 8192)])), val)
		}
		if matched {
			add("CUSTOM_"+rule.ID, "rule/"+rule.Kind, rule.Name+" · "+rule.Value, rule.Score)
			if rule.Action != "" && forced == "" {
				// Rules are sorted by descending priority: first forced action wins.
				forced = rule.Action
			}
		}
	}
	ruleDetail := fmt.Sprintf("Checked %d enabled, non-expired rule(s) for matching conditions", eligibleRules)
	if mixedRecipientRuleSkips > 0 {
		ruleDetail += fmt.Sprintf("; skipped %d recipient-specific rule(s) for mixed envelope recipients (one Milter verdict per transaction)", mixedRecipientRuleSkips)
	}
	note("Custom filtering rules", matchedSince(rulesStart), ruleDetail)
	dnsStart := len(findings)
	dnsEnabled := 0
	for _, z := range cfg.DNSLists {
		if z.Enabled {
			dnsEnabled++
		}
	}
	dnsErrors := 0
	dnsChecked := 0
	if cfg.Settings.DNSBLEnabled {
		// Bound total external DNSBL work to 3 seconds even when many zones
		// are configured; normal authentication DNS has its own budget.
		reputationCtx, cancelReputation := context.WithTimeout(ctx, 3*time.Second)
		defer cancelReputation()
		zonesUsed := 0
		for _, zone := range cfg.DNSLists {
			if zonesUsed >= 8 || reputationCtx.Err() != nil {
				break
			}
			if zone.Enabled {
				zonesUsed++
			}
			if !zone.Enabled {
				continue
			}
			kind := zone.Kind
			if kind == "" {
				kind = "ip"
			}
			var names []string
			switch kind {
			case "ip":
				if m.ClientIP != "" {
					names = append(names, m.ClientIP)
				}
			case "domain":
				if senderDomain != "" {
					names = append(names, senderDomain)
				}
			case "url":
				for d := range domains {
					names = append(names, d)
				}
				sort.Strings(names)
				if len(names) > 4 {
					names = names[:4]
				}
			}
			if len(names) == 0 {
				note("DNS blocklist: "+zone.Zone, "skipped", "No eligible "+kind+" address or domain")
			}
			for _, candidate := range names {
				var detail string
				var listed bool
				var err error
				if kind == "ip" {
					detail, listed, err = dnsblLookup(reputationCtx, s.Resolver, candidate, zone.Zone)
				} else {
					detail, listed, err = domainDNSBLLookup(reputationCtx, s.Resolver, candidate, zone.Zone)
				}
				if detail != "" {
					dnsChecked++
				}
				if err != nil {
					dnsErrors++
					note("DNS blocklist: "+zone.Zone, "error", "DNS lookup unavailable: "+err.Error())
				} else if listed {
					add("DNSBL_"+strings.ToUpper(kind)+"_"+strings.ReplaceAll(zone.Zone, ".", "_"), "dnsbl/"+kind+"/"+zone.Zone, detail, zone.Score)
				}
			}
		}
	}
	if !cfg.Settings.DNSBLEnabled || dnsEnabled == 0 {
		note("DNS blocklists", "skipped", "Disabled or no blocklist zones enabled")
	} else {
		status := matchedSince(dnsStart)
		if dnsChecked == 0 && dnsErrors == 0 {
			status = "skipped"
		}
		note("DNS blocklists", status, fmt.Sprintf("Queried %d IP/domain/URL zone entries; %d DNS error(s). Lists are individually opt-in and require supported DNSBL A reply codes.", dnsChecked, dnsErrors))
	}
	if cfg.Settings.ThreatFeedEnabled {
		candidates := make([]string, 0, len(domains)+1)
		if senderDomain != "" {
			candidates = append(candidates, senderDomain)
		}
		for d := range domains {
			candidates = append(candidates, d)
		}
		sort.Strings(candidates)
		matched, err := FindThreatFeedMatches(m.ClientIP, candidates)
		if err != nil {
			note("External threat feed", "error", err.Error())
		} else {
			total := 0.0
			for _, item := range matched {
				weight := 3.0
				if total >= 9 {
					break
				}
				total += weight
				add(item.Symbol, "external/feed", item.Detail, weight)
			}
			if len(matched) > 0 {
				note("External threat feed", "match", fmt.Sprintf("%d matched indicator(s); snapshot is opt-in and expires automatically", len(matched)))
			} else {
				note("External threat feed", "clear", "No matches in current trusted snapshot")
			}
		}
	} else {
		note("External threat feed", "skipped", "Disabled; no local intelligence snapshot consulted")
	}
	spf := SPFResult{Result: "none"}
	if in.ClientIP != "" {
		spf = SPFCheck(ctx, s.Resolver, in.ClientIP, in.Sender, in.Helo)
		switch spf.Result {
		case "pass":
			add("R_SPF_ALLOW", "auth/spf/"+spf.Domain, spf.Explanation, -1)
		case "fail":
			add("R_SPF_FAIL", "auth/spf/"+spf.Domain, spf.Explanation, 4)
		case "softfail":
			add("R_SPF_SOFTFAIL", "auth/spf/"+spf.Domain, spf.Explanation, 1.5)
		case "permerror":
			add("R_SPF_PERMERROR", "auth/spf/"+spf.Domain, spf.Explanation, 1)
		}
	}
	if in.ClientIP == "" {
		note("SPF sender authorization", "skipped", "No original sending IP supplied")
	} else {
		note("SPF sender authorization", spf.Result, fmt.Sprintf("Source IP %s; envelope domain %s. %s", in.ClientIP, spf.Domain, spf.Explanation))
	}
	dkimResults := DKIMVerify(ctx, s.Resolver, in.Raw)
	// One message may carry multiple DKIM signatures. Count verified
	// authentication once; never let an attacker force quarantine simply by
	// prepending ten invalid DKIM-Signature headers to otherwise valid mail.
	signaturePass, signatureFail := 0, 0
	var passSig, failSig DKIMResult
	for _, dkim := range dkimResults {
		if dkim.Result == "pass" {
			signaturePass++
			passSig = dkim
		}
		if dkim.Result == "fail" {
			signatureFail++
			if failSig.Domain == "" {
				failSig = dkim
			}
		}
	}
	if signaturePass > 0 {
		add("R_DKIM_ALLOW", "auth/dkim/"+passSig.Domain, fmt.Sprintf("%d verified signature(s); %d other signature(s) failed", signaturePass, signatureFail), -1)
	} else if signatureFail > 0 {
		add("R_DKIM_REJECT", "auth/dkim/"+failSig.Domain, fmt.Sprintf("%d failed signature(s), no verified signature. First: %s", signatureFail, failSig.Detail), 2)
	}
	if len(dkimResults) == 0 {
		note("DKIM digital signatures", "skipped", "No DKIM signatures found")
	} else {
		for _, d := range dkimResults {
			note("DKIM digital signatures", d.Result, fmt.Sprintf("DNS public key: %s._domainkey.%s; %s", d.Selector, d.Domain, d.Detail))
		}
	}
	// Cryptographic ARC validation is evidence only: never treat signed forwarding
	// chain as a trusted sender without an explicit trusted-sealer policy.
	arc := ValidateARC(ctx, s.Resolver, in.Raw)
	switch arc.Status {
	case "malformed":
		add("ARC_MALFORMED", "auth/arc", arc.Detail, 0)
	case "pass":
		add("ARC_CRYPTO_PASS", "auth/arc", arc.Detail, 0)
	case "fail", "temperror":
		add("ARC_CRYPTO_"+strings.ToUpper(arc.Status), "auth/arc", arc.Detail, 0)
	}
	note("ARC forwarding chain", arc.Status, arc.Detail+". ARC does not override DMARC or establish intermediary trust")
	dmarc := DMARCCheck(ctx, s.Resolver, parsed.Header.Get("From"), spf, dkimResults)
	switch dmarc.Result {
	case "pass":
		add("DMARC_PASS", "auth/dmarc/"+dmarc.Domain, dmarc.Detail, -1)
	case "fail":
		// RFC 9989 t=y test mode lowers the requested policy one level.
		// Historic pct= has no effect. This is score input, not direct MTA
		// enforcement, and authentication evidence is retained.
		effective := effectiveDMARCPolicy(dmarc)
		weight := 0.0
		if effective == "quarantine" {
			weight = 4
		}
		if effective == "reject" {
			weight = 6
		}
		detail := fmt.Sprintf("%s; effective scoring policy=%s (t=%t; RFC 9989)", dmarc.Detail, effective, dmarc.Testing)
		add("DMARC_FAIL", "auth/dmarc/"+dmarc.Domain, detail, weight)
		if dmarc.Testing {
			note("DMARC policy test mode", "info", fmt.Sprintf("Published p=%s t=y; effective policy=%s; authentication still failed", dmarc.Policy, effective))
		}
	case "permerror":
		add("DMARC_PERMERROR", "auth/dmarc/"+dmarc.Domain, dmarc.Detail, 1)
	}
	note("DMARC identity alignment", dmarc.Result, fmt.Sprintf("Policy: %s. %s. DMARC depends on SPF/DKIM results; its weight is not independent evidence of a third failure.", dmarc.Policy, dmarc.Detail))
	if cfg.Settings.ReviewedReputation && dmarc.Result == "pass" {
		review := s.Store.ReviewedDomainReputation(dmarc.Domain)
		if review.Ready {
			if review.Weight != 0 {
				add("REVIEWED_DOMAIN_REPUTATION", "learning/reviewed/"+dmarc.Domain, fmt.Sprintf("Authenticated domain with %d confirmed spam and %d false-positive reviews; score adjusted only, no forced action", review.ConfirmedSpam, review.ConfirmedHam), review.Weight)
			}
			note("Reviewed sender reputation", "info", fmt.Sprintf("Authenticated %s has %d confirmed spam and %d legitimate corrections", dmarc.Domain, review.ConfirmedSpam, review.ConfirmedHam))
		} else {
			note("Reviewed sender reputation", "skipped", "Fewer than four reviewed, DMARC-authenticated samples for this domain")
		}
	} else {
		note("Reviewed sender reputation", "skipped", "Opt-in disabled or sender has not passed DMARC")
	}

	bayes, bayesErr := s.Store.ScoreBayes(in.Raw)
	if bayesErr == nil && bayes.Ready {
		if bayes.Probability >= 0.95 {
			add("BAYES_SPAM", "learning/bayes", fmt.Sprintf("%.1f%% spam probability (%d spam / %d ham samples)", bayes.Probability*100, bayes.Spam, bayes.Ham), 3.5)
		}
		if bayes.Probability <= 0.05 {
			add("BAYES_HAM", "learning/bayes", fmt.Sprintf("%.1f%% spam probability (%d spam / %d ham samples)", bayes.Probability*100, bayes.Spam, bayes.Ham), -2)
		}
	}
	if bayesErr != nil {
		note("Bayesian learning", "error", bayesErr.Error())
	} else if !bayes.Ready {
		note("Bayesian learning", "skipped", "Not yet trained with enough confirmed spam and legitimate messages")
	} else {
		note("Bayesian learning", "info", fmt.Sprintf("Estimated spam probability: %.1f%%", bayes.Probability*100))
	}
	fuzzy, fuzzyErr := s.Store.ScoreFuzzy(in.Raw)
	if fuzzyErr == nil && fuzzy.Matched {
		detail := fmt.Sprintf("near-duplicate of trained %s sample %s (similarity %.1f%%, distance %d/64)", fuzzy.Label, fuzzy.ID, fuzzy.Similarity*100, fuzzy.Distance)
		if fuzzy.Label == "spam" {
			add("FUZZY_SPAM", "learning/fuzzy/"+fuzzy.ID, detail, 6)
		} else {
			add("FUZZY_HAM", "learning/fuzzy/"+fuzzy.ID, detail, -3)
		}
	}
	if fuzzyErr != nil {
		note("Near-duplicate learning", "error", fuzzyErr.Error())
	} else if fuzzy.Matched {
		note("Near-duplicate learning", "match", fmt.Sprintf("Similarity %.1f%% to trained %s", fuzzy.Similarity*100, fuzzy.Label))
	} else {
		note("Near-duplicate learning", "clear", "No matching trained fingerprint")
	}
	if cfg.Settings.ExternalFuzzyEnabled {
		external, err := CheckRemoteFuzzy(ctx, in.Raw)
		if err != nil {
			note("External fuzzy intelligence", "error", "Remote provider unavailable or fingerprint ineligible: "+err.Error())
		} else if external.Label == "spam" && external.Confidence >= 0.95 && external.Samples >= 5 {
			add("REMOTE_FUZZY_SPAM", "learning/remote-fuzzy", fmt.Sprintf("Provider %s; confidence %.2f; %d samples; only SimHash fingerprint shared", external.Provider, external.Confidence, external.Samples), 2)
			note("External fuzzy intelligence", "match", "High-confidence fingerprint match (max +2, never a forced action)")
		} else {
			note("External fuzzy intelligence", "clear", "No qualifying high-confidence spam fingerprint match")
		}
	} else {
		note("External fuzzy intelligence", "skipped", "Disabled; no data transferred to external providers")
	}
	neural := s.Store.ScoreNeural(findings)
	if neural.Ready {
		if neural.Probability >= 0.9 {
			add("NEURAL_SPAM", "learning/neural", fmt.Sprintf("%.1f%% spam probability, manually trained on %d messages", neural.Probability*100, neural.Ham+neural.Spam), 3)
		}
		if neural.Probability <= 0.1 {
			add("NEURAL_HAM", "learning/neural", fmt.Sprintf("%.1f%% spam probability, manually trained on %d messages", neural.Probability*100, neural.Ham+neural.Spam), -2)
		}
	}
	if neural.Ready {
		note("Neural learning", "info", fmt.Sprintf("Estimated spam probability: %.1f%%", neural.Probability*100))
	} else {
		note("Neural learning", "skipped", "Not yet trained with enough confirmed labels")
	}
	malware, avErr := ClamAVScan(ctx, in.Raw)
	if avErr != nil {
		return Message{}, fmt.Errorf("antivirus service unavailable or scan failed: %w", avErr)
	}
	if os.Getenv("SPAMGATE_CLAMAV_ADDRESS") == "" {
		note("Antivirus", "skipped", "No ClamAV service configured")
	} else if malware == "" {
		note("Antivirus", "clear", "ClamAV did not report a signature")
	} else {
		note("Antivirus", "match", "ClamAV reported: "+malware)
	}
	if malware != "" {
		add("CLAMAV_MALWARE", "antivirus/clamav", malware, 100)
		forced = "reject"
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Score > findings[j].Score })
	score := 0.0
	for _, f := range findings {
		score += f.Score
	}
	score = float64(int(score*100+sign(score)*0.5)) / 100
	m.Score = score
	trace.ForcedAction = forced
	m.Scoring = trace
	m.Findings = findings
	switch {
	case score >= cfg.Settings.RejectThreshold:
		m.Action = "reject"
	case score >= cfg.Settings.QuarantineThreshold:
		m.Action = "quarantine"
	case score >= cfg.Settings.TagThreshold:
		m.Action = "tag"
	}
	if forced != "" {
		m.Action = forced
		add("FORCED_ACTION", "policy/override", "Rule forces "+forced, 0)
		m.Findings = findings
	}
	m.TestCase = testID
	m.Category, m.Categories = ClassifyCategories(m.Findings, m.Action, testID)
	m.ScanDurationMS = time.Since(started).Milliseconds()
	return m, nil
}
func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
