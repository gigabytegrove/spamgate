package transport

// Wire-level Sendmail/Postfix Milter v6 compatibility connector. This connector
// intentionally requests all envelope/header/body callbacks rather than
// pretending to support unimplemented SMTP-stage mutation operations.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

const (
	milterMaxFrame     = 64 << 10
	milterMaxMessage   = 10 << 20
	milterAddHeader    = uint32(0x1)
	milterQuarantine   = uint32(0x20)
	milterChangeHeader = uint32(0x10)
)

type Milter struct {
	Addr    string
	Trusted []*net.IPNet
	Store   *core.Store
	Scanner *core.Scanner
}

func MilterFromEnv(store *core.Store) (*Milter, error) {
	addr := strings.TrimSpace(os.Getenv("SPAMGATE_MILTER_LISTEN"))
	if addr == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("invalid SPAMGATE_MILTER_LISTEN: %w", err)
	}
	trusted := strings.TrimSpace(os.Getenv("SPAMGATE_MILTER_TRUSTED_CIDRS"))
	if trusted == "" {
		return nil, errors.New("SPAMGATE_MILTER_TRUSTED_CIDRS is required for milter listener")
	}
	cidrs, err := parseTrustedCIDRs(trusted)
	if err != nil {
		return nil, err
	}
	return &Milter{Addr: addr, Trusted: cidrs, Store: store, Scanner: &core.Scanner{Store: store}}, nil
}
func (m *Milter) Listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	slots := make(chan struct{}, 64)
	slog.Info("milter worker listening", "address", m.Addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		peer, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		allowed := err == nil
		ip := net.ParseIP(peer)
		allowed = allowed && ip != nil
		if allowed {
			allowed = false
			for _, n := range m.Trusted {
				if n.Contains(ip) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				if err := m.handle(ctx, conn); err != nil && !errors.Is(err, io.EOF) {
					slog.Warn("milter connection terminated", "error", err)
				}
			}()
		default:
			_ = conn.Close()
		}
	}
}

func readMilterFrame(r io.Reader) (byte, []byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 1 || n > milterMaxFrame {
		return 0, nil, fmt.Errorf("invalid milter frame length %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	return data[0], data[1:], nil
}
func writeMilterFrame(w io.Writer, command byte, data []byte) error {
	if len(data)+1 > milterMaxFrame {
		return errors.New("milter response too large")
	}
	out := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(1+len(data)))
	out[4] = command
	copy(out[5:], data)
	// Short writes are legal for io.Writer; a partial Milter response
	// must never be mistaken for a successfully transmitted frame.
	for len(out) > 0 {
		n, err := w.Write(out)
		if n < 0 || n > len(out) {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		out = out[n:]
	}
	return nil
}
func firstMilterString(b []byte) string {
	if p := bytes.IndexByte(b, 0); p >= 0 {
		b = b[:p]
	}
	return strings.Trim(string(b), "<> \t\r\n")
}
func milterAddress(b []byte) string {
	zero := bytes.IndexByte(b, 0)
	if zero < 0 || len(b) < zero+4 {
		return ""
	}
	family := b[zero+1]
	if family != '4' && family != '6' {
		return ""
	}
	address := firstMilterString(b[zero+4:])
	if net.ParseIP(address) == nil {
		return ""
	}
	return address
}

// Parse a trusted MTA-supplied queue ID from the Sendmail Milter macro packet.
// Macro keys are NUL-delimited, preceded by one callback-stage byte.
func milterQueueID(data []byte) string {
	// Require a stage byte and complete NUL-terminated name/value pairs.
	// Incomplete or ambiguous MTA queue evidence must never be trusted.
	if len(data) < 4 || data[len(data)-1] != 0 {
		return ""
	}
	parts := bytes.Split(data[1:len(data)-1], []byte{0})
	if len(parts)%2 != 0 {
		return ""
	}
	var id string
	for i := 0; i < len(parts); i += 2 {
		name := strings.Trim(string(parts[i]), "{}")
		if name != "i" {
			continue
		}
		if id != "" {
			return "" // duplicate queue ID macro is ambiguous
		}
		value := string(parts[i+1])
		if len(value) < 1 || len(value) > 32 {
			return ""
		}
		for _, c := range value {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				return ""
			}
		}
		id = value
	}
	return id
}
func milterHeader(data []byte) ([]byte, error) {
	fields := bytes.SplitN(data, []byte{0}, 3)
	if len(fields) != 3 || len(fields[2]) != 0 || len(fields[0]) == 0 || bytes.ContainsAny(fields[0], "\r\n:") {
		return nil, errors.New("invalid milter header name")
	}
	for _, c := range fields[0] {
		if c < 33 || c > 126 {
			return nil, errors.New("invalid milter header byte")
		}
	}
	v := bytes.TrimRight(fields[1], "\r\n")
	// RFC 5322 allows folding at CRLF followed by SP/HTAB. Postfix may
	// forward this as either CRLF or bare LF in a Milter header callback.
	// Normalize line endings, but never permit an unindented new field to
	// be injected into the message header block.
	clean := make([]byte, 0, len(v)+8)
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\r':
			if i+1 >= len(v) || v[i+1] != '\n' {
				return nil, errors.New("bare carriage return in milter header")
			}
			i++
			fallthrough
		case '\n':
			if i+1 >= len(v) || (v[i+1] != ' ' && v[i+1] != '\t') {
				return nil, errors.New("invalid header continuation: newline not followed by whitespace")
			}
			clean = append(clean, '\r', '\n')
		default:
			clean = append(clean, v[i])
		}
	}
	line := make([]byte, 0, len(fields[0])+len(clean)+4)
	line = append(line, fields[0]...)
	line = append(line, ':', ' ')
	line = append(line, clean...)
	line = append(line, '\r', '\n')
	return line, nil
}

// Tagging adds traceable headers; final folder placement remains the MTA's
// responsibility. Identifiers and scores are generated internally (no mail
// content is reflected into header values).
func milterTagHeaders(msg core.Message) [][2]string {
	threshold := 5.0
	if msg.Scoring != nil {
		threshold = msg.Scoring.TagThreshold
	}
	return [][2]string{
		{"X-Spam", "Yes"},
		{"X-Spam-Status", fmt.Sprintf("Yes, score=%.2f required=%.2f", msg.Score, threshold)},
		{"X-SpamGate-Score", fmt.Sprintf("%.2f", msg.Score)},
		{"X-SpamGate-Action", msg.Action},
		{"X-SpamGate-ID", msg.ID},
	}
}

func (m *Milter) handle(ctx context.Context, conn net.Conn) error {
	type transaction struct {
		sender       string
		mailSeen     bool // distinguishes a null MAIL FROM from no MAIL callback
		recipients   []string
		headers      bytes.Buffer
		body         bytes.Buffer
		hasEOH       bool
		queueID      string
		spoofHeaders []string
		poisoned     bool // any failed callback invalidates this entire transaction
	}
	var msg transaction
	var clientIP string
	var helo string
	var negotiated bool
	var actions uint32
	reset := func() { msg = transaction{} }
	for {
		_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
		cmd, data, err := readMilterFrame(conn)
		if err != nil {
			return err
		}
		if !negotiated && cmd != 'O' {
			return errors.New("milter option negotiation required")
		}
		reply := byte('c')
		switch cmd {
		case 'O':
			if negotiated || len(data) < 12 {
				return errors.New("invalid milter negotiation")
			}
			version := binary.BigEndian.Uint32(data[:4])
			if version < 2 {
				return errors.New("unsupported milter version")
			}
			offered := binary.BigEndian.Uint32(data[4:8])
			actions = offered & (milterAddHeader | milterQuarantine | milterChangeHeader)
			selected := version
			if selected > 6 {
				selected = 6
			}
			response := make([]byte, 12)
			binary.BigEndian.PutUint32(response[0:4], selected)
			binary.BigEndian.PutUint32(response[4:8], actions)
			// Request all callbacks; announce no unsupported protocol shortcuts.
			binary.BigEndian.PutUint32(response[8:12], 0)
			slog.Debug("milter protocol negotiated", "version", selected,
				"can_add_header", actions&milterAddHeader != 0,
				"can_quarantine", actions&milterQuarantine != 0)
			negotiated = true
			if err := writeMilterFrame(conn, 'O', response); err != nil {
				return err
			}
			continue
		case 'D': // Macro definition does not expect a response.
			// Only a new queue ID after MAIL FROM is associated with the
			// current transaction, preventing reuse from a previous email.
			if id := milterQueueID(data); id != "" && msg.mailSeen {
				msg.queueID = id
			}
			continue
		case 'C':
			clientIP = milterAddress(data)
		case 'H':
			helo = firstMilterString(data)
		case 'M':
			reset()
			msg.mailSeen = true
			msg.sender = firstMilterString(data)
		case 'R':
			if !msg.mailSeen || msg.poisoned || msg.hasEOH {
				msg.poisoned = true
				reply = 't'
				break
			}
			if v := firstMilterString(data); v != "" {
				msg.recipients = append(msg.recipients, v)
			}
		case 'L':
			if !msg.mailSeen || msg.poisoned || msg.hasEOH {
				msg.poisoned = true
				reply = 't'
				break
			}
			line, err := milterHeader(data)
			if err != nil {
				slog.Warn("milter rejected header callback", "reason", "invalid_header", "error", err)
				msg.poisoned = true
				reply = 't'
				break
			}
			if msg.headers.Len()+len(line) > milterMaxMessage {
				slog.Warn("milter rejected header callback", "reason", "headers_exceed_message_size_limit")
				msg.poisoned = true
				reply = 't'
				break
			}
			name := string(line[:bytes.IndexByte(line, ':')])
			if strings.HasPrefix(strings.ToLower(name), "x-spamgate-") || strings.EqualFold(name, "X-Spam") || strings.EqualFold(name, "X-Spam-Status") {
				msg.spoofHeaders = append(msg.spoofHeaders, name)
				if len(msg.spoofHeaders) > 100 {
					slog.Warn("Milter received excessive untrusted SpamGate headers")
					msg.poisoned = true
					reply = 't'
					break
				}
			}
			_, _ = msg.headers.Write(line)
		case 'N':
			if !msg.mailSeen || msg.poisoned {
				msg.poisoned = true
				reply = 't'
				break
			}
			msg.hasEOH = true
		case 'T', 'U': // DATA and unknown SMTP commands; continue
		case 'B':
			if !msg.mailSeen || !msg.hasEOH || msg.poisoned {
				msg.poisoned = true
				reply = 't'
				break
			}
			if msg.body.Len()+len(data) > milterMaxMessage {
				slog.Warn("milter rejected body callback", "reason", "body_exceeds_message_size_limit")
				msg.poisoned = true
				reply = 't'
				break
			}
			_, _ = msg.body.Write(data)
		case 'A':
			reset()
			continue
		case 'K':
			reset()
			clientIP = ""
			continue
		case 'Q':
			return nil
		case 'E':
			// A failed header/body callback must never be followed by an
			// accepted end-of-message using a truncated or altered original.
			if msg.poisoned || !msg.mailSeen || len(msg.recipients) == 0 {
				slog.Warn("milter refused incomplete transaction", "reason", "failed_callback_or_missing_envelope")
				reply = 't'
				reset()
				break
			}
			if !msg.hasEOH {
				slog.Warn("milter could not finish message", "reason", "missing_end_of_headers")
				reply = 't'
				reset()
				break
			}
			if msg.headers.Len()+msg.body.Len()+2 > milterMaxMessage {
				slog.Warn("milter could not finish message", "reason", "message_too_large")
				reply = 't'
				reset()
				break
			}
			raw := make([]byte, 0, msg.headers.Len()+msg.body.Len()+2)
			raw = append(raw, msg.headers.Bytes()...)
			raw = append(raw, '\r', '\n')
			raw = append(raw, msg.body.Bytes()...)
			if !m.Store.Config().SetupComplete {
				slog.Warn("milter could not finish message", "reason", "administrator_setup_incomplete")
				reply = 't'
				reset()
				break
			}
			// Bound each message scan independently of the long-lived listener.
			scanCtx, cancelScan := context.WithTimeout(ctx, 45*time.Second)
			scanned, err := m.Scanner.Scan(scanCtx, core.Input{Raw: raw, Sender: msg.sender, Recipients: msg.recipients, ClientIP: clientIP, Helo: helo, Connector: "milter"})
			cancelScan()
			if err != nil {
				slog.Error("milter could not finish message", "reason", "scan_failed", "error", err)
				reply = 't'
				reset()
				break
			}
			scanned.MTAQueueID = msg.queueID
			settings := m.Store.Config().Settings
			if len(msg.spoofHeaders) > 0 && actions&milterChangeHeader == 0 {
				scanned.Action = "soft_reject"
				scanned.Findings = append(scanned.Findings, core.Finding{Symbol: "UNTRUSTED_SPAMGATE_HEADER", Source: "policy/milter", Detail: "Incoming message claimed SpamGate headers but Postfix did not permit stripping them", Score: 0})
				slog.Warn("milter cannot strip untrusted incoming SpamGate headers", "scan_id", scanned.ID)
			}
			if policyAction, reason, policyErr := m.Store.EvaluateDeliveryPolicy(scanned, time.Now()); policyErr != nil {
				slog.Error("milter delivery policy persistence failure", "error", policyErr)
				reply = 't'
				reset()
				break
			} else if policyAction == "soft_reject" {
				scanned.Action = "soft_reject"
				scanned.Findings = append(scanned.Findings, core.Finding{Symbol: "TEMPORARY_POLICY_DEFERRAL", Source: "policy/delivery", Detail: reason, Score: 0})
				if scanned.Scoring != nil {
					scanned.Scoring.Checks = append(scanned.Scoring.Checks, core.ScanCheck{Name: "SMTP abuse controls", Status: "match", Detail: reason})
				}
			}
			// Milter commands are requests to Postfix. An accepted Milter
			// callback is not proof of mailbox delivery, and queue holds are
			// NOT Dovecot Junk-folder placement. Record the intended command
			// before replying, without claiming downstream success.
			switch scanned.Action {
			case "quarantine":
				if settings.QuarantineMode == "junk" {
					if actions&milterAddHeader != 0 {
						scanned.MTAAction = "junk_header_requested"
						scanned.MTAActionNote = "Requested spam headers for Dovecot Sieve Junk routing. Postfix delivery and mailbox placement are not confirmed."
					} else {
						scanned.MTAAction = "temporary_failure_requested"
						scanned.MTAActionNote = "Missing header addition capability required for Junk routing."
					}
				} else if actions&milterQuarantine != 0 {
					scanned.MTAAction = "postfix_hold_requested"
					scanned.MTAActionNote = "Requested Postfix Milter quarantine/hold. Check Postfix hold queue; not proof of hold or Junk delivery."
				} else {
					scanned.MTAAction = "temporary_failure_requested"
					scanned.MTAActionNote = "Postfix did not negotiate Milter quarantine capability; requested SMTP temporary failure."
				}
			case "tag":
				if actions&milterAddHeader != 0 {
					scanned.MTAAction = "spam_header_requested"
					scanned.MTAActionNote = "Requested X-Spam: Yes, X-Spam-Status, score, action and scan-ID headers. Junk-folder routing requires a separate MTA/Sieve rule."
				} else {
					scanned.MTAAction = "temporary_failure_requested"
					scanned.MTAActionNote = "Postfix did not negotiate header addition; requested SMTP temporary failure."
				}
			case "soft_reject":
				scanned.MTAAction = "smtp_temporary_failure_requested"
				scanned.MTAActionNote = "Requested temporary SMTP rejection per configured greylisting or rate limit; sending MTA may retry later."
			case "reject":
				scanned.MTAAction = "smtp_reject_requested"
				scanned.MTAActionNote = "Requested Postfix to reject the message in SMTP. Confirm using Postfix logs."
			default:
				scanned.MTAAction = "continue_requested"
				scanned.MTAActionNote = "Requested Postfix to continue delivery; SpamGate has no downstream delivery receipt."
			}
			scanned.MTAActionState = "requested"
			if err = m.Store.Save(scanned); err != nil {
				slog.Error("milter could not finish message", "reason", "history_write_failed", "error", err)
				reply = 't'
				reset()
				break
			}
			// Remove incoming spam verdict headers before adding SpamGate-trusted ones.
			// Otherwise a sender can forge X-SpamGate-Action, X-Spam or X-Spam-Status and misroute Junk.
			if actions&milterChangeHeader != 0 {
				for _, name := range msg.spoofHeaders {
					packet := make([]byte, 4)
					binary.BigEndian.PutUint32(packet, 1)
					packet = append(packet, []byte(name+"\x00\x00")...)
					if err := writeMilterFrame(conn, 'm', packet); err != nil {
						return err
					}
				}
			}
			slog.Info("milter verdict recorded", "scan_id", scanned.ID, "message_id", scanned.MessageID,
				"client_ip", scanned.ClientIP, "score", scanned.Score, "action", scanned.Action,
				"mta_action", scanned.MTAAction)
			switch scanned.Action {
			case "reject":
				reply = 'r'
			case "soft_reject":
				reply = 't'
			case "quarantine":
				if settings.QuarantineMode == "junk" {
					if actions&milterAddHeader != 0 {
						for _, header := range milterTagHeaders(scanned) {
							if err := writeMilterFrame(conn, 'h', []byte(header[0]+"\x00"+header[1]+"\x00")); err != nil {
								return err
							}
						}
						reply = 'c'
					} else {
						reply = 't'
					}
				} else if actions&milterQuarantine != 0 {
					if err := writeMilterFrame(conn, 'q', []byte("SpamGate quarantine\x00")); err != nil {
						return err
					}
					reply = 'c'
				} else {
					slog.Warn("milter could not enforce message verdict", "reason", "quarantine_action_not_negotiated", "scan_id", scanned.ID)
					reply = 't'
				} // fail closed, do not silently deliver a hold verdict
			case "tag":
				if actions&milterAddHeader != 0 {
					for _, header := range milterTagHeaders(scanned) {
						data := []byte(header[0] + "\x00" + header[1] + "\x00")
						if err := writeMilterFrame(conn, 'h', data); err != nil {
							return err
						}
					}
					if settings.SubjectRewrite {
						if actions&milterChangeHeader != 0 {
							subject := scanned.Subject
							if subject != "" && !strings.ContainsAny(subject, "\r\n\x00") && len(subject) <= 400 && !strings.HasPrefix(strings.ToUpper(subject), "[SPAM]") {
								packet := make([]byte, 4)
								binary.BigEndian.PutUint32(packet, 1)
								packet = append(packet, []byte("Subject\x00[SPAM] "+subject+"\x00")...)
								if err := writeMilterFrame(conn, 'm', packet); err != nil {
									return err
								}
							}
						} else {
							slog.Warn("MTA did not negotiate subject modification; spam headers still added", "scan_id", scanned.ID)
						}
					}
					reply = 'c'
				} else {
					slog.Warn("milter could not enforce message verdict", "reason", "add_header_action_not_negotiated", "scan_id", scanned.ID)
					reply = 't'
				}
			default:
				reply = 'c'
			}
			reset()
		default:
			return fmt.Errorf("unsupported milter command %q", cmd)
		}
		if err := writeMilterFrame(conn, reply, nil); err != nil {
			return err
		}
	}
}
