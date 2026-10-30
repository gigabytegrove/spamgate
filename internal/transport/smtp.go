package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

type Relay struct{ Address, Username, Password, TLSMode string }

func RelayFromEnv() (*Relay, error) {
	addr := os.Getenv("SPAMGATE_RELAY_ADDRESS")
	if addr == "" {
		return nil, nil
	}
	host, port, e := net.SplitHostPort(addr)
	if e != nil || host == "" || port == "" {
		return nil, errors.New("SPAMGATE_RELAY_ADDRESS must be host:port")
	}
	mode := os.Getenv("SPAMGATE_RELAY_TLS")
	if mode == "" {
		mode = "required"
	}
	if mode != "required" && mode != "implicit" && mode != "none" {
		return nil, errors.New("SPAMGATE_RELAY_TLS must be required, implicit or none")
	}
	r := &Relay{Address: addr, Username: os.Getenv("SPAMGATE_RELAY_USERNAME"), Password: os.Getenv("SPAMGATE_RELAY_PASSWORD"), TLSMode: mode}
	if r.Username != "" && mode == "none" {
		return nil, errors.New("authentication over plaintext SMTP is forbidden")
	}
	return r, nil
}
func (r *Relay) Send(ctx context.Context, m core.Message, raw []byte) error {
	if r == nil {
		return errors.New("no relay configured")
	}
	host, _, e := net.SplitHostPort(r.Address)
	if e != nil {
		return e
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, e := d.DialContext(ctx, "tcp", r.Address)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
	if r.TLSMode == "implicit" {
		conn = tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if e = conn.(*tls.Conn).HandshakeContext(ctx); e != nil {
			return fmt.Errorf("relay TLS: %w", e)
		}
	}
	client, e := smtp.NewClient(conn, host)
	if e != nil {
		return e
	}
	defer client.Close()
	if r.TLSMode == "required" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("relay does not advertise STARTTLS")
		}
		if e = client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); e != nil {
			return e
		}
	}
	if r.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", r.Username, r.Password, host)); e != nil {
			return e
		}
	}
	sender := strings.TrimSpace(m.Sender)
	if sender == "" {
		sender = "<>"
	}
	sender = strings.Trim(sender, "<>")
	if e = client.Mail(sender); e != nil {
		return fmt.Errorf("relay MAIL: %w", e)
	}
	if len(m.Recipients) == 0 {
		return errors.New("no recipients")
	}
	for _, recipient := range m.Recipients {
		if e = client.Rcpt(recipient); e != nil {
			return fmt.Errorf("relay RCPT: %w", e)
		}
	}
	writer, e := client.Data()
	if e != nil {
		return e
	}
	if _, e = writer.Write(raw); e != nil {
		return e
	}
	if e = writer.Close(); e != nil {
		return fmt.Errorf("relay DATA: %w", e)
	}
	_ = client.Quit()
	return nil
}

type SMTP struct {
	Queue   *DeliveryQueue
	Store   *core.Store
	Scanner *core.Scanner
	Relay   *Relay
	Addr    string
	CIDRs   []*net.IPNet
	Domains []string
	log     *slog.Logger
}

func SMTPFromEnv(store *core.Store, relay *Relay) (*SMTP, error) {
	addr := os.Getenv("SPAMGATE_SMTP_LISTEN")
	if addr == "" {
		return nil, nil
	}
	if relay == nil {
		return nil, errors.New("SMTP listener requires SPAMGATE_RELAY_ADDRESS")
	}
	cidrText := os.Getenv("SPAMGATE_SMTP_TRUSTED_CIDRS")
	domainText := os.Getenv("SPAMGATE_ALLOWED_RECIPIENT_DOMAINS")
	if cidrText == "" || domainText == "" {
		return nil, errors.New("SMTP listener requires explicit trusted CIDRs and recipient domains")
	}
	s := &SMTP{Store: store, Scanner: &core.Scanner{Store: store}, Relay: relay, Addr: addr, log: slog.Default()}
	for _, piece := range strings.Split(cidrText, ",") {
		piece = strings.TrimSpace(piece)
		if ip := net.ParseIP(piece); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			piece += "/" + strconv.Itoa(bits)
		}
		_, network, e := net.ParseCIDR(piece)
		if e != nil {
			return nil, fmt.Errorf("invalid SMTP trusted CIDR: %w", e)
		}
		s.CIDRs = append(s.CIDRs, network)
	}
	for _, piece := range strings.Split(domainText, ",") {
		piece = strings.ToLower(strings.TrimSpace(piece))
		if piece == "" || strings.ContainsAny(piece, " @:/\\") || !strings.Contains(piece, ".") {
			return nil, errors.New("invalid allowed recipient domain")
		}
		s.Domains = append(s.Domains, piece)
	}
	return s, nil
}
func (s *SMTP) Listen(ctx context.Context) error {
 // The native SMTP listener must never accept a message without the
 // fsync-backed outbox. Direct relay before SMTP 250 has ambiguous outcomes.
 if s.Queue == nil { return errors.New("SMTP listener requires a durable delivery queue") }
 listener, e := net.Listen("tcp", s.Addr)
	if e != nil {
		return e
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	slots := make(chan struct{}, 64)
	s.log.Info("SMTP content filter listening", "address", s.Addr)
	for {
		conn, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); s.handle(conn) }()
		default:
			_, _ = io.WriteString(conn, "421 SpamGate busy\r\n")
			_ = conn.Close()
		}
	}
}
func (s *SMTP) allowedPeer(remote net.Addr) bool {
	host, _, e := net.SplitHostPort(remote.String())
	if e != nil {
		return false
	}
	ip := net.ParseIP(host)
	for _, n := range s.CIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
func (s *SMTP) allowedRecipient(address string) bool {
	p := strings.LastIndex(address, "@")
	if p < 0 {
		return false
	}
	domain := strings.ToLower(address[p+1:])
	for _, d := range s.Domains {
		if domain == d {
			return true
		}
	}
	return false
}
func readLineLimited(reader *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		part, e := reader.ReadSlice('\n')
		if len(out)+len(part) > limit {
			return nil, errors.New("SMTP line too long")
		}
		out = append(out, part...)
		if e == nil {
			return out, nil
		}
		if !errors.Is(e, bufio.ErrBufferFull) {
			return nil, e
		}
	}
}
func (s *SMTP) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Minute))
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriter(conn)
	reply := func(code int, msg string) { _, _ = fmt.Fprintf(writer, "%d %s\r\n", code, msg); _ = writer.Flush() }
	if !s.allowedPeer(conn.RemoteAddr()) {
		reply(554, "5.7.1 Client network not trusted")
		return
	}
	reply(220, "SpamGate ESMTP filtering gateway ready")
	var sender string
	var recipients []string
	greeted := false
	heloName := ""
	mailIssued := false
	forwardedIP := ""
	forwardedHelo := ""
	seenForwardedIP := false
	seenForwardedHelo := false
	// DATA completion (including errors) ends the transaction. Never let
	// a client reuse its sender, recipients, or XFORWARD identity.
	resetEnvelope := func() {
		sender = ""
		recipients = nil
		mailIssued = false
		forwardedIP = ""
		forwardedHelo = ""
		seenForwardedIP = false
		seenForwardedHelo = false
	}
	for commands := 0; commands < 500; commands++ {
		lineBytes, e := readLineLimited(reader, 4096)
		line := string(lineBytes)
		if e != nil {
			return
		}
		if len(line) > 4096 {
			reply(500, "5.5.2 Command line too long")
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			reply(500, "5.5.2 Empty command")
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO "):
			if strings.TrimSpace(line[5:]) == "" {
				reply(501, "5.5.2 EHLO requires a client identity")
				continue
			}
			heloName = strings.TrimSpace(line[5:])
			greeted = true
			forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
			forwardedHelo = ""
			mailIssued = false
			sender = ""
			recipients = nil
			_, _ = io.WriteString(writer, "250-SpamGate\r\n250-XFORWARD ADDR\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n")
			_ = writer.Flush()
		case strings.HasPrefix(upper, "HELO "):
			if strings.TrimSpace(line[5:]) == "" {
				reply(501, "5.5.2 HELO requires a client identity")
				continue
			}
			heloName = strings.TrimSpace(line[5:])
			greeted = true
			forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
			forwardedHelo = ""
			mailIssued = false
			sender = ""
			recipients = nil
			reply(250, "SpamGate")
		case upper == "NOOP":
			reply(250, "2.0.0 OK")
		case upper == "RSET":
			mailIssued = false
			forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
			forwardedHelo = ""
			sender = ""
			recipients = nil
			reply(250, "2.0.0 Reset")
		case upper == "QUIT":
			reply(221, "2.0.0 Bye")
			return
		case strings.HasPrefix(upper, "XFORWARD "):
			if !greeted || mailIssued {
				reply(503, "5.5.1 XFORWARD only before MAIL FROM")
				continue
			}
			// Postfix may split XFORWARD metadata across commands. Preserve the
			// original HELO alongside ADDR: SPF for MAIL FROM:<> uses HELO,
			// never the intermediate content-filter gateway's greeting.
			proposedIP, proposedHelo := "", ""
			hasIP, hasHelo, invalid := false, false, false
			for _, field := range strings.Fields(line[len("XFORWARD "):]) {
				key, value, ok := strings.Cut(field, "=")
				if !ok || value == "" {
					invalid = true
					break
				}
				switch strings.ToUpper(key) {
				case "ADDR":
					if hasIP {
						invalid = true
						break
					}
					candidate := strings.Trim(value, "[]")
					candidate = strings.TrimPrefix(candidate, "IPv6:")
					if net.ParseIP(candidate) == nil {
						invalid = true
						break
					}
					proposedIP, hasIP = candidate, true
				case "HELO":
					if hasHelo || len(value) > 255 || strings.ContainsAny(value, "\r\n\x00") {
						invalid = true
						break
					}
					proposedHelo, hasHelo = value, true
					if value == "[UNAVAILABLE]" || value == "[TEMPUNAVAIL]" {
						proposedHelo = ""
					}
				}
				if invalid {
					break
				}
			}
			if invalid || (!hasIP && !hasHelo) || (hasIP && seenForwardedIP) || (hasHelo && seenForwardedHelo) {
				reply(501, "5.5.2 Invalid or duplicate XFORWARD identity")
				continue
			}
			if hasIP {
				forwardedIP = proposedIP
				seenForwardedIP = true
			}
			if hasHelo {
				forwardedHelo = proposedHelo
				seenForwardedHelo = true
			}
			reply(250, "2.0.0 Original SMTP identity recorded")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			if !greeted {
				reply(503, "5.5.1 HELO first")
				continue
			}
			// A new MAIL command starts a new transaction, including when invalid.
   // Never accidentally reuse an earlier sender or recipient set.
   sender = ""
   recipients = nil
   mailIssued = false
   addr, declaredSize, e := parseSMTPMail(line)
   if e != nil {
    reply(501, "5.5.4 Invalid MAIL FROM path or unsupported ESMTP parameter")
    continue
   }
   if declaredSize > 10<<20 {
    reply(552, "5.3.4 Declared message size exceeds 10485760 bytes")
    continue
   }
   sender = addr
			mailIssued = true
			recipients = nil
			reply(250, "2.1.0 Sender accepted")
		case strings.HasPrefix(upper, "RCPT TO:"):
			if !greeted {
				reply(503, "5.5.1 HELO first")
				continue
			}
			if !mailIssued {
				reply(503, "5.5.1 Need MAIL FROM first")
				continue
			}
			addr, e := parseSMTPRecipient(line)
			if e != nil || addr == "" {
				reply(501, "5.1.3 Invalid recipient")
				continue
			}
			if !s.allowedRecipient(addr) {
				reply(550, "5.7.1 Relaying denied for recipient domain")
				continue
			}
			if len(recipients) >= 100 {
				reply(452, "4.5.3 Too many recipients")
				continue
			}
			recipients = append(recipients, addr)
			reply(250, "2.1.5 Recipient accepted")
		case upper == "DATA":
			if !s.Store.Config().SetupComplete {
				reply(451, "4.3.0 SpamGate requires initial setup")
				continue
			}
			if !mailIssued || len(recipients) == 0 {
				reply(503, "5.5.1 Need RCPT TO first")
				continue
			}
			reply(354, "End data with <CR><LF>.<CR><LF>")
			var raw bytes.Buffer
			tooLarge := false
			terminated := false
			for {
				part, e := readLineLimited(reader, 16*1024)
				if e != nil {
					return
				}
				if bytes.Equal(part, []byte(".\r\n")) || bytes.Equal(part, []byte(".\n")) {
					terminated = true
					break
				}
				if len(part) > 0 && part[0] == '.' {
					part = part[1:]
				}
				if raw.Len()+len(part) > 10<<20 {
					tooLarge = true
				} else if !tooLarge {
					raw.Write(part)
				}
			}
			if !terminated || tooLarge {
				reply(552, "5.3.4 Message too large")
				sender = ""
				mailIssued = false
				forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
				forwardedHelo = ""
				recipients = nil
				continue
			}
			clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			originIP := clientIP
			if forwardedIP != "" {
				originIP = forwardedIP
			}
			originHelo := heloName
			if forwardedHelo != "" {
				originHelo = forwardedHelo
			}
			scanCtx, cancelScan := context.WithTimeout(context.Background(), 45*time.Second)
   m, e := s.Scanner.Scan(scanCtx, core.Input{Raw: raw.Bytes(), Sender: sender, Recipients: recipients, ClientIP: originIP, Helo: originHelo, Connector: "smtp"})
   cancelScan()
			if e == nil {
				m.IngestIP = clientIP
			}
			if e != nil {
				// Malformed originals are permanent errors; unavailable AV, DNS,
				// timeouts and internal scanner errors must remain retryable.
				slog.Error("SMTP content scan failed", "error", e)
				if errors.Is(e, core.ErrInvalidMessage) {
					reply(550, "5.6.0 Invalid RFC 5322 message")
				} else {
					reply(451, "4.3.0 Content scanner temporarily unavailable")
				}
				resetEnvelope()
				continue
			}
			if m.Action == "quarantine" {
				if e = s.Store.Quarantine(m.ID, raw.Bytes()); e != nil {
					slog.Error("SMTP quarantine persistence failed", "error", e)
					reply(451, "4.3.0 Could not save quarantine")
					resetEnvelope()
					continue
				}
			}
			if m.Action == "reject" {
				m.Delivery = "rejected"
				if e = s.Store.Save(m); e != nil {
					reply(451, "4.3.0 Cannot write audit log")
				} else {
					reply(550, "5.7.1 Rejected by SpamGate id="+m.ID)
				}
				sender = ""
				mailIssued = false
				forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
				forwardedHelo = ""
				recipients = nil
				continue
			}
			if m.Action == "quarantine" {
				m.Delivery = "quarantined"
				if e = s.Store.Save(m); e != nil {
					reply(451, "4.3.0 Cannot write audit log")
				} else {
					reply(250, "2.0.0 Quarantined id="+m.ID)
				}
				sender = ""
				mailIssued = false
				forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
				forwardedHelo = ""
				recipients = nil
				continue
			}
			if s.Queue != nil {
				// A successful spool fsync transfers SMTP delivery responsibility.
				m.Delivery = "queued"
				queuedRaw := raw.Bytes()
				if m.Action == "tag" {
					prefix := fmt.Sprintf("X-SpamGate-Result: tag\r\nX-SpamGate-Score: %.2f\r\nX-SpamGate-ID: %s\r\n", m.Score, m.ID)
					queuedRaw = append([]byte(prefix), queuedRaw...)
				}
				if e = s.Queue.Enqueue(m, queuedRaw); e != nil {
					s.log.Error("durable queue could not accept message", "id", m.ID, "error", e)
					reply(451, "4.3.0 Durable queue unavailable")
				} else {
					// Queue is authoritative: failure to mirror into history must NOT
					// make the client retry an already durably accepted message.
					if e = s.Store.Save(m); e != nil {
						s.log.Error("queued mail history record failed", "id", m.ID, "error", e)
					}
					reply(250, "2.0.0 Queued id="+m.ID)
				}
				sender = ""
				mailIssued = false
				forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
				forwardedHelo = ""
				recipients = nil
				continue
			}
			m.Delivery = "pending"
			if e = s.Store.Save(m); e != nil {
				reply(451, "4.3.0 Cannot write audit log")
				sender = ""
				mailIssued = false
				forwardedIP = ""
			seenForwardedIP = false
			seenForwardedHelo = false
				forwardedHelo = ""
				recipients = nil
				continue
			}
			outgoing := raw.Bytes()
			if m.Action == "tag" {
				prefix := fmt.Sprintf("X-SpamGate-Result: tag\r\nX-SpamGate-Score: %.2f\r\nX-SpamGate-ID: %s\r\n", m.Score, m.ID)
				outgoing = append([]byte(prefix), outgoing...)
			}
			relayCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			e = s.Relay.Send(relayCtx, m, outgoing)
			cancel()
			if e != nil {
				s.log.Error("SMTP relay failure", "id", m.ID, "error", e)
				m.Delivery = "relay_failed"
				_ = s.Store.Save(m)
				reply(451, "4.4.1 Upstream delivery unavailable")
			} else {
				m.Delivery = "relayed"
				if saveErr := s.Store.Save(m); saveErr != nil {
					s.log.Error("post-delivery audit update failed", "id", m.ID, "error", saveErr)
				}
				reply(250, "2.0.0 Accepted id="+m.ID)
			}
			resetEnvelope()
		default:
			reply(502, "5.5.1 Command not supported")
		}
	}
	reply(421, "4.5.3 Too many commands")
}
