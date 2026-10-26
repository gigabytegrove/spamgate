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
	milterMaxFrame   = 64 << 10
	milterMaxMessage = 10 << 20
	milterAddHeader  = uint32(0x1)
	milterQuarantine = uint32(0x20)
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
	_, err := w.Write(out)
	return err
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
func milterHeader(data []byte) ([]byte, error) {
	fields := bytes.SplitN(data, []byte{0}, 3)
	if len(fields) != 3 || len(fields[0]) == 0 || bytes.ContainsAny(fields[0], "\r\n:") {
		return nil, errors.New("invalid milter header name")
	}
	for _, c := range fields[0] {
		if c < 33 || c > 126 {
			return nil, errors.New("invalid milter header byte")
		}
	}
	v := bytes.TrimRight(fields[1], "\r\n")
	// Don't let malformed callbacks turn a single field into arbitrary headers.
	if bytes.ContainsAny(v, "\r\n") {
		return nil, errors.New("multiline milter headers unsupported")
	}
	line := make([]byte, 0, len(fields[0])+len(v)+4)
	line = append(line, fields[0]...)
	line = append(line, ':', ' ')
	line = append(line, v...)
	line = append(line, '\r', '\n')
	return line, nil
}
func (m *Milter) handle(ctx context.Context, conn net.Conn) error {
	type transaction struct {
		sender     string
		recipients []string
		headers    bytes.Buffer
		body       bytes.Buffer
		hasEOH     bool
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
			actions = offered & (milterAddHeader | milterQuarantine)
			selected := version
			if selected > 6 {
				selected = 6
			}
			response := make([]byte, 12)
			binary.BigEndian.PutUint32(response[0:4], selected)
			binary.BigEndian.PutUint32(response[4:8], actions)
			// Request all callbacks; announce no unsupported protocol shortcuts.
			binary.BigEndian.PutUint32(response[8:12], 0)
			negotiated = true
			if err := writeMilterFrame(conn, 'O', response); err != nil {
				return err
			}
			continue
		case 'D': // Macro definition does not expect a response.
			continue
		case 'C':
			clientIP = milterAddress(data)
		case 'H':
			helo = firstMilterString(data)
		case 'M':
			reset()
			msg.sender = firstMilterString(data)
		case 'R':
			if v := firstMilterString(data); v != "" {
				msg.recipients = append(msg.recipients, v)
			}
		case 'L':
			line, err := milterHeader(data)
			if err != nil {
				reply = 't'
				break
			}
			if msg.headers.Len()+len(line) > milterMaxMessage {
				reply = 't'
				break
			}
			_, _ = msg.headers.Write(line)
		case 'N':
			msg.hasEOH = true
		case 'T', 'U': // DATA and unknown SMTP commands; continue
		case 'B':
			if msg.body.Len()+len(data) > milterMaxMessage {
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
			if !msg.hasEOH || msg.headers.Len()+msg.body.Len()+2 > milterMaxMessage {
				reply = 't'
				reset()
				break
			}
			raw := make([]byte, 0, msg.headers.Len()+msg.body.Len()+2)
			raw = append(raw, msg.headers.Bytes()...)
			raw = append(raw, '\r', '\n')
			raw = append(raw, msg.body.Bytes()...)
			if !m.Store.Config().SetupComplete {
				reply = 't'
				reset()
				break
			}
			scanned, err := m.Scanner.Scan(ctx, core.Input{Raw: raw, Sender: msg.sender, Recipients: msg.recipients, ClientIP: clientIP, Helo: helo, Connector: "milter"})
			if err != nil {
				reply = 't'
				reset()
				break
			}
			if err = m.Store.Save(scanned); err != nil {
				reply = 't'
				reset()
				break
			}
			switch scanned.Action {
			case "reject":
				reply = 'r'
			case "quarantine":
				if actions&milterQuarantine != 0 {
					if err := writeMilterFrame(conn, 'q', []byte("SpamGate quarantine\x00")); err != nil {
						return err
					}
					reply = 'c'
				} else {
					reply = 't'
				} // fail closed, do not silently deliver a hold verdict
			case "tag":
				if actions&milterAddHeader != 0 {
					if err := writeMilterFrame(conn, 'h', []byte("X-Spam\x00Yes\x00")); err != nil {
						return err
					}
					reply = 'c'
				} else {
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
