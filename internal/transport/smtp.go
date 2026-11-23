package transport

import (
	"bufio"
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
	if _, err := validateRelayEndpoint(addr); err != nil {
		return nil, fmt.Errorf("SPAMGATE_RELAY_ADDRESS: %w", err)
	}
	mode := os.Getenv("SPAMGATE_RELAY_TLS")
	if mode == "" {
		mode = "required"
	}
	if mode != "required" && mode != "implicit" && mode != "none" {
		return nil, errors.New("SPAMGATE_RELAY_TLS must be required, implicit or none")
	}
	r := &Relay{Address: addr, Username: os.Getenv("SPAMGATE_RELAY_USERNAME"), Password: os.Getenv("SPAMGATE_RELAY_PASSWORD"), TLSMode: mode}
	if err := r.validateConfiguration(); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Relay) Send(ctx context.Context, m core.Message, raw []byte) error {
	if r == nil {
		return errors.New("no relay configured")
	}
	// Validate immutable spool contents before any DNS, TLS, AUTH or socket work.
	// Invalid originals must enter dead-letter even while the relay is down.
	if err := validateRelayOriginal(m, raw); err != nil {
		return wrapInvalidRelayOriginal(err)
	}
	// Validate at the last responsible boundary as well as environment
	// construction: tests, integrations and future callers build Relay directly.
	// Never open a socket before rejecting unsafe authentication settings.
	if err := r.validateConfiguration(); err != nil {
		return err
	}
	host, e := validateRelayEndpoint(r.Address)
	if e != nil {
		return e
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, e := d.DialContext(ctx, "tcp", r.Address)
	if e != nil {
		return e
	}
	defer conn.Close()
	// A shorter caller deadline must govern the entire SMTP transaction,
	// including greeting, EHLO, TLS, AUTH, RCPT, DATA and final response.
	// A fixed 40-second socket deadline alone does not honor cancellation.
	deadline := time.Now().Add(40 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return fmt.Errorf("relay socket deadline: %w", e)
	}
	// Capture the underlying connection: conn is reassigned to tls.Client
	// for implicit TLS and must not race the cancellation callback.
	baseConn := conn
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = baseConn.SetDeadline(time.Now())
	})
	defer stopCancellation()
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
		// Refuse unadvertised authentication before exposing credentials.
		// This must inspect the post-STARTTLS EHLO capability set.
		if e = requireRelayPlainAuth(client); e != nil {
			return e
		}
		if e = client.Auth(smtp.PlainAuth("", r.Username, r.Password, host)); e != nil {
			return e
		}
	}
	// Capability checks must precede MAIL FROM: an incompatible next hop
	// cannot be allowed to downgrade original bytes or UTF-8 recipients.
	if e = checkRelayCapabilities(client, m, raw); e != nil {
		return e
	}
	sender := strings.TrimSpace(m.Sender)
	if sender == "" {
		sender = "<>"
	}
	sender = strings.Trim(sender, "<>")
	if e = client.Mail(sender); e != nil {
		return wrapRelayStage("MAIL", e)
	}
	if len(m.Recipients) == 0 {
		return errors.New("no recipients")
	}
	// Replayed legacy envelopes may contain duplicate RCPT entries. Avoid
	// sending an identical recipient twice to the downstream relay.
	for _, recipient := range uniqueSMTPRecipients(m.Recipients) {
		if e = client.Rcpt(recipient); e != nil {
			return wrapRelayStage("RCPT", e)
		}
	}
	writer, e := client.Data()
	if e != nil {
		return wrapRelayStage("DATA", e)
	}
	if _, e = writer.Write(raw); e != nil {
		return wrapRelayStage("DATA", e)
	}
	if e = writer.Close(); e != nil {
		return wrapRelayStage("DATA", e)
	}
	// The final 250 after DATA is the delivery acceptance boundary. Do not
	// wait for a QUIT response: some relays keep that response pending, and
	// delaying success can trigger upstream retries of an accepted message.
	// The deferred client.Close closes the SMTP connection immediately.
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
		network, e := parseSMTPTrustedNetwork(piece)
		if e != nil {
			return nil, fmt.Errorf("invalid SMTP trusted CIDR: %w", e)
		}
		s.CIDRs = append(s.CIDRs, network)
	}
	for _, piece := range strings.Split(domainText, ",") {
		piece = strings.TrimSpace(piece)
		// Validate the raw configured DNS name before any case conversion.
		// Unicode simple-case conversion can map lookalikes such as U+212A
		// (Kelvin sign) onto ASCII k, silently authorizing another domain.
		if !isASCIIDomain(piece) || !validSMTPRecipientDomain(piece) {
			return nil, errors.New("invalid allowed recipient domain")
		}
		s.Domains = append(s.Domains, strings.ToLower(piece))
	}
	return s, nil
}
func (s *SMTP) logger() *slog.Logger {
	if s != nil && s.log != nil { return s.log }
	return slog.Default()
}

func (s *SMTP) Listen(ctx context.Context) error {
 // The native SMTP listener must never accept a message without the
 // fsync-backed outbox. Direct relay before SMTP 250 has ambiguous outcomes.
 if err := s.validateListenerPreflight(); err != nil { return err }
 listener, e := net.Listen("tcp", s.Addr)
	if e != nil {
		return e
	}
	defer listener.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()
	slots := make(chan struct{}, 64)
	logger := s.logger()
	logger.Info("SMTP content filter listening", "address", s.Addr)
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
			// Do not perform network I/O on the accept goroutine when saturated.
			// A peer that never reads 421 could otherwise stall all new accepts.
			rejectBusySMTPConnection(conn)
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
	// Authorization is intentionally independent of the SMTP command parser.
	// A future caller must not turn a malformed envelope with an extra @,
	// empty mailbox or Unicode domain into an authorized relay recipient.
	at := strings.IndexByte(address, '@')
	if at <= 0 || at == len(address)-1 || strings.IndexByte(address[at+1:], '@') >= 0 || !validSMTPAuthorizationLocalPart(address[:at]) {
		return false
	}
	domain := address[at+1:]
	// DNS domain case is ASCII-only. Never Unicode-fold a lookalike into
	// an allowlisted name before validating the configured DNS syntax.
	for i := 0; i < len(domain); i++ {
		if domain[i] > 0x7f {
			return false
		}
	}
	if !validSMTPRecipientDomain(strings.ToLower(domain)) {
		return false
	}
	for _, allowed := range s.Domains {
		if equalASCIIDNSDomain(domain, allowed) {
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
	logger := s.logger()
	// Bound both total session lifetime and each idle command wait. A trusted
	// Postfix peer must not occupy one of the 64 connection slots indefinitely.
	// The fixed session deadline remains an upper bound even when commands flow.
	sessionDeadline := time.Now().Add(4 * time.Minute)
	_ = conn.SetDeadline(sessionDeadline)
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriter(conn)
	reply := func(code int, msg string) { if err := smtpWriteResponse(conn, writer, fmt.Sprintf("%d %s\r\n", code, msg)); err != nil { logger.Debug("SMTP response write failed", "error", err) } }
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
	mailParams := smtpMailParameters{DeclaredSize: -1}
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
		mailParams = smtpMailParameters{DeclaredSize: -1}
		forwardedIP = ""
		forwardedHelo = ""
		seenForwardedIP = false
		seenForwardedHelo = false
	}
	for commands := 0; commands < 500; commands++ {
		// A silent or stalled peer cannot hold a listener slot for the entire
		// four-minute transaction budget. Do not extend the total deadline.
		_ = conn.SetReadDeadline(smtpCommandDeadline(time.Now(), sessionDeadline, 30*time.Second))
		line, commandErr := readSMTPCommand(reader)
		if commandErr != nil {
			var netErr net.Error
			if errors.As(commandErr, &netErr) && netErr.Timeout() {
				reply(421, "4.4.2 SMTP command timeout")
			} else if !errors.Is(commandErr, io.EOF) {
				reply(500, "5.5.2 Invalid SMTP command framing")
			}
			return
		}
		// DATA may require the remainder of the session budget to transmit
		// the advertised 10 MiB maximum; remove the short command timeout.
		_ = conn.SetReadDeadline(sessionDeadline)
		// Validate the exact wire command before dispatch. Trimming first can
		// turn malformed command framing into an authorized SMTP transaction.
		if !validSMTPCommandWire(line) {
			reply(500, "5.5.2 Invalid SMTP command syntax")
			continue
		}
		rawCommand := line
		if line == "" {
			reply(500, "5.5.2 Empty command")
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO "):
			if !validSMTPGreetingIdentity(rawCommand[5:]) {
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
			mailParams = smtpMailParameters{DeclaredSize: -1}
			if err := smtpWriteResponse(conn, writer, "250-SpamGate\r\n250-XFORWARD ADDR\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n"); err != nil { logger.Debug("SMTP EHLO response failed", "error", err); return }
		case strings.HasPrefix(upper, "HELO "):
			if !validSMTPGreetingIdentity(rawCommand[5:]) {
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
			mailParams = smtpMailParameters{DeclaredSize: -1}
			reply(250, "SpamGate")
		case upper == "NOOP":
			reply(250, "2.0.0 OK")
		case upper == "RSET":
			mailIssued = false
			mailParams = smtpMailParameters{DeclaredSize: -1}
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
					candidate, valid := parseSMTPXForwardAddress(value)
					if !valid {
						invalid = true
						break
					}
					proposedIP, hasIP = candidate, true
				case "HELO":
					if hasHelo {
						invalid = true
						break
					}
					candidateHelo, valid := parseSMTPXForwardHelo(value)
					if !valid {
						invalid = true
						break
					}
					proposedHelo, hasHelo = candidateHelo, true
				default:
					// Unknown metadata must not be silently accepted as an identity.
					invalid = true
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
   mailParams = smtpMailParameters{DeclaredSize: -1}
   addr, parsedParams, e := parseSMTPMailParameters(line)
   if e != nil {
    reply(501, "5.5.4 Invalid MAIL FROM path or unsupported ESMTP parameter")
    continue
   }
   if parsedParams.DeclaredSize > 10<<20 {
    reply(552, "5.3.4 Declared message size exceeds 10485760 bytes")
    continue
   }
   sender = addr
   mailParams = parsedParams
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
			// An exact duplicate is already part of this transaction and must
			// remain idempotently accepted even at the distinct-recipient cap.
			// Reject only a *new* mailbox when all 100 slots are occupied.
			var accepted bool
			recipients, accepted = acceptSMTPRecipient(recipients, addr, 100)
			if !accepted {
				reply(452, "4.5.3 Too many recipients")
				continue
			}
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
			raw, dataErr := readSMTPData(reader, 10<<20)
			if dataErr != nil {
				// A failed DATA read cannot establish the next SMTP command
				// boundary. In particular, an oversized DATA body may still
				// contain lines resembling MAIL/RCPT commands. Never resume
				// command parsing on the same connection after a read failure.
				code, message := smtpDataReadFailureReply(dataErr)
				logger.Warn("SMTP DATA read failed; closing session", "error", dataErr, "smtp_code", code)
				reply(code, message)
				return
			}
			if wireErr := validateRelayWireData(raw); wireErr != nil {
				reply(554, "5.6.0 Original cannot be transmitted over SMTP DATA")
				resetEnvelope()
				continue
			}
			// SIZE and BODY declarations are part of the accepted SMTP
			// transaction. Refuse violations before scanning or durable 250.
			if contractErr := validateSMTPDataContract(mailParams, raw); contractErr != nil {
				if errors.Is(contractErr, errSMTPDeclaredSize) {
					reply(552, "5.3.4 Message exceeds declared MAIL SIZE")
				} else if errors.Is(contractErr, errSMTPBody7Bit) {
					reply(554, "5.6.0 8-bit DATA requires BODY=8BITMIME")
				} else {
					reply(554, "5.6.0 SMTPUTF8 header fields not supported")
				}
				resetEnvelope()
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
   m, e := s.Scanner.Scan(scanCtx, core.Input{Raw: raw, Sender: sender, Recipients: recipients, ClientIP: originIP, Helo: originHelo, Connector: "smtp"})
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
				if e = s.Store.Quarantine(m.ID, raw); e != nil {
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
				queuedRaw := raw
				if m.Action == "tag" {
					prefix := fmt.Sprintf("X-SpamGate-Result: tag\r\nX-SpamGate-Score: %.2f\r\nX-SpamGate-ID: %s\r\n", m.Score, m.ID)
					queuedRaw = append([]byte(prefix), queuedRaw...)
				}
				// Generated tag headers must not turn an accepted original into
				// an undeliverable dead-letter record after SMTP 250.
				if wireErr := validateRelayWireData(queuedRaw); wireErr != nil {
					slog.Error("tagged message exceeds SMTP relay wire limits", "id", m.ID, "error", wireErr)
					reply(552, "5.3.4 Tagged message exceeds SMTP relay wire limits")
					resetEnvelope()
					continue
				}
				// The queue must never acknowledge an original that the delivery
				// worker will deterministically dead-letter on its first attempt.
				// Apply the same offline validation at SMTP acceptance and replay.
				if preflightErr := validateRelayOriginal(m, queuedRaw); preflightErr != nil {
					logger.Warn("SMTP original failed relay preflight", "id", m.ID, "error", preflightErr)
					reply(554, "5.6.0 Original cannot be relayed safely")
					resetEnvelope()
					continue
				}
				if e = s.Queue.Enqueue(m, queuedRaw); e != nil {
					logger.Error("durable queue could not accept message", "id", m.ID, "error", e)
					reply(451, "4.3.0 Durable queue unavailable")
				} else {
					// Queue is authoritative: failure to mirror into history must NOT
					// make the client retry an already durably accepted message.
					if e = s.Store.Save(m); e != nil {
						logger.Error("queued mail history record failed", "id", m.ID, "error", e)
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
			outgoing := raw
			if m.Action == "tag" {
				prefix := fmt.Sprintf("X-SpamGate-Result: tag\r\nX-SpamGate-Score: %.2f\r\nX-SpamGate-ID: %s\r\n", m.Score, m.ID)
				outgoing = append([]byte(prefix), outgoing...)
			}
			relayCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			e = s.Relay.Send(relayCtx, m, outgoing)
			cancel()
			if e != nil {
				logger.Error("SMTP relay failure", "id", m.ID, "error", e)
				m.Delivery = "relay_failed"
				_ = s.Store.Save(m)
				reply(451, "4.4.1 Upstream delivery unavailable")
			} else {
				m.Delivery = "relayed"
				if saveErr := s.Store.Save(m); saveErr != nil {
					logger.Error("post-delivery audit update failed", "id", m.ID, "error", saveErr)
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
