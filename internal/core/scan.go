package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
func bodyParts(h mail.Header, body []byte, depth int) (string, []string, []string, bool) {
	if depth > 8 {
		return "", nil, nil, false
	}
	media, params, e := mime.ParseMediaType(h.Get("Content-Type"))
	if e != nil {
		media = "text/plain"
	}
	if strings.HasPrefix(media, "multipart/") {
		if params["boundary"] == "" {
			return "", nil, nil, false
		}
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		var all strings.Builder
		var attachments, urls []string
		hasHTML := false
		for count := 0; count < 75; count++ {
			part, e := reader.NextPart()
			if e != nil {
				break
			}
			p, e := io.ReadAll(io.LimitReader(part, 5<<20))
			if e != nil {
				part.Close()
				break
			}
			text, a, u, html := bodyParts(mail.Header(part.Header), p, depth+1)
			all.WriteString(text)
			all.WriteByte(' ')
			attachments = append(attachments, a...)
			urls = append(urls, u...)
			hasHTML = hasHTML || html
			part.Close()
		}
		return all.String(), attachments, urls, hasHTML
	}
	name := params["name"]
	if disposition, ps, e := mime.ParseMediaType(h.Get("Content-Disposition")); e == nil {
		if ps["filename"] != "" {
			name = ps["filename"]
		}
		if disposition == "attachment" && name == "" {
			name = "unnamed attachment"
		}
	}
	if name != "" {
		return "", []string{name}, nil, false
	}
	if media != "text/plain" && media != "text/html" {
		return "", nil, nil, false
	}
	// Decode transfer encodings that commonly appear in mail bodies.
	encoding := strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding")))
	var decoded []byte
	switch encoding {
	case "base64":
		decoded = decodeBase64(body)
	case "quoted-printable":
		decoded = decodeQP(body)
	default:
		decoded = body
	}
	if len(decoded) > 2<<20 {
		decoded = decoded[:2<<20]
	}
	text := string(decoded)
	matches := urlPattern.FindAllString(text, 100)
	if media == "text/html" {
		text = htmlTag.ReplaceAllString(text, " ")
	}
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

// Decoding functions are in codec.go to isolate MIME transfer handling.
func (s *Scanner) Scan(ctx context.Context, in Input) (Message, error) {
	if len(in.Raw) == 0 || len(in.Raw) > 10<<20 {
		return Message{}, fmt.Errorf("message size must be 1–10485760 bytes")
	}
	cfg := s.Store.Config()
	m := Message{ID: ID(), Timestamp: time.Now().UTC(), Sender: strings.TrimSpace(in.Sender), Recipients: append([]string(nil), in.Recipients...), ClientIP: in.ClientIP, Connector: in.Connector, Size: len(in.Raw), Action: "accept"}
	parsed, e := mail.ReadMessage(bytes.NewReader(in.Raw))
	if e != nil {
		return Message{}, fmt.Errorf("invalid RFC 5322 message: %w", e)
	}
	m.MessageID = parsed.Header.Get("Message-Id")
	m.Subject = decodedHeader(parsed.Header.Get("Subject"))
	if m.Sender == "" {
		m.Sender = parsed.Header.Get("From")
	}
	body, e := io.ReadAll(io.LimitReader(parsed.Body, 10<<20))
	if e != nil {
		return Message{}, e
	}
	text, attachments, urls, hasHTML := bodyParts(parsed.Header, body, 0)
	var findings []Finding
	add := func(symbol, source, detail string, weight float64) {
		if strings.HasPrefix(source, "builtin/") || strings.HasPrefix(source, "auth/") || strings.HasPrefix(source, "antivirus/") || strings.HasPrefix(source, "learning/") {
			if p, ok := cfg.SignalPolicies[symbol]; ok {
				if !p.Enabled {
					return
				}
				weight = p.Score
			}
		}
		findings = append(findings, Finding{symbol, source, detail, weight})
	}
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
	lower := strings.ToLower(m.Subject + " " + text)
	for _, rule := range suspiciousWords {
		if strings.Contains(lower, rule.word) {
			add("CONTENT_"+strings.ToUpper(strings.ReplaceAll(rule.word, " ", "_")), "builtin/content", rule.word, rule.weight)
		}
	}
	for _, a := range attachments {
		ext := strings.ToLower(a)
		for _, risky := range []string{".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".jar", ".docm", ".xlsm", ".lnk", ".iso"} {
			if strings.HasSuffix(ext, risky) {
				add("RISKY_ATTACHMENT", "builtin/attachment", a, 5)
				break
			}
		}
		if strings.Contains(ext, ".pdf.exe") || strings.Contains(ext, ".jpg.exe") {
			add("DOUBLE_EXTENSION", "builtin/attachment", a, 4)
		}
	}
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
	// Rules are evaluated after built-ins and retain provenance and their configured weight.
	forced := ""
	senderDomain := strings.ToLower(strings.TrimSpace(m.Sender))
	if p := strings.LastIndex(senderDomain, "@"); p >= 0 {
		senderDomain = senderDomain[p+1:]
	}
	for _, rule := range cfg.Rules {
		if !rule.Enabled || strings.TrimSpace(rule.Value) == "" {
			continue
		}
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
			for _, r := range m.Recipients {
				if strings.EqualFold(r, rule.Value) {
					matched = true
				}
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
			if rule.Action != "" {
				forced = rule.Action
			}
		}
	}
	if cfg.Settings.DNSBLEnabled && m.ClientIP != "" {
		ip := net.ParseIP(m.ClientIP)
		if ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			v4 := ip.To4()
			rev := strconv.Itoa(int(v4[3])) + "." + strconv.Itoa(int(v4[2])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[0]))
			for _, zone := range cfg.DNSLists {
				if !zone.Enabled {
					continue
				}
				name := rev + "." + zone.Zone
				dnsCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
				ips, err := net.DefaultResolver.LookupHost(dnsCtx, name)
				cancel()
				if err == nil && len(ips) > 0 {
					add("DNSBL_"+strings.ReplaceAll(zone.Zone, ".", "_"), "dnsbl/"+zone.Zone, "listed: "+name, zone.Score)
				}
			}
		}
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
	dkimResults := DKIMVerify(ctx, s.Resolver, in.Raw)
	for _, dkim := range dkimResults {
		switch dkim.Result {
		case "pass":
			add("R_DKIM_ALLOW", "auth/dkim/"+dkim.Domain, dkim.Detail, -1)
		case "fail":
			add("R_DKIM_REJECT", "auth/dkim/"+dkim.Domain, dkim.Detail, 2)
		}
	}
	// Structural ARC evidence is informational only. Never promote an ARC
	// "cv=pass" claim to authentication without cryptographic verification.
	arc := CheckARCStructure(in.Raw)
	switch arc.Status {
	case "malformed":
		add("ARC_MALFORMED", "auth/arc", arc.Detail, 0)
	case "unverified":
		add("ARC_UNVERIFIED", "auth/arc", arc.Detail, 0)
	}
	dmarc := DMARCCheck(ctx, s.Resolver, parsed.Header.Get("From"), spf, dkimResults)
	switch dmarc.Result {
	case "pass":
		add("DMARC_PASS", "auth/dmarc/"+dmarc.Domain, dmarc.Detail, -1)
	case "fail":
		weight := 0.0
		if dmarc.Policy == "quarantine" {
			weight = 4
		}
		if dmarc.Policy == "reject" {
			weight = 6
		}
		add("DMARC_FAIL", "auth/dmarc/"+dmarc.Domain, dmarc.Detail, weight)
	case "permerror":
		add("DMARC_PERMERROR", "auth/dmarc/"+dmarc.Domain, dmarc.Detail, 1)
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
	if fuzzy, err := s.Store.ScoreFuzzy(in.Raw); err == nil && fuzzy.Matched {
		detail := fmt.Sprintf("near-duplicate of trained %s sample %s (similarity %.1f%%, distance %d/64)", fuzzy.Label, fuzzy.ID, fuzzy.Similarity*100, fuzzy.Distance)
		if fuzzy.Label == "spam" {
			add("FUZZY_SPAM", "learning/fuzzy/"+fuzzy.ID, detail, 6)
		} else {
			add("FUZZY_HAM", "learning/fuzzy/"+fuzzy.ID, detail, -3)
		}
	}
	if neural := s.Store.ScoreNeural(findings); neural.Ready {
		if neural.Probability >= 0.9 {
			add("NEURAL_SPAM", "learning/neural", fmt.Sprintf("%.1f%% spam probability, manually trained on %d messages", neural.Probability*100, neural.Ham+neural.Spam), 3)
		}
		if neural.Probability <= 0.1 {
			add("NEURAL_HAM", "learning/neural", fmt.Sprintf("%.1f%% spam probability, manually trained on %d messages", neural.Probability*100, neural.Ham+neural.Spam), -2)
		}
	}
	malware, avErr := ClamAVScan(ctx, in.Raw)
	if avErr != nil {
		return Message{}, fmt.Errorf("antivirus service unavailable or scan failed: %w", avErr)
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
