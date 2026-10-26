package core

// ClamAV clamd INSTREAM protocol client. The scan fails closed when clamd is
// enabled but unreachable; it never silently treats AV errors as clean mail.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func ClamAVScan(ctx context.Context, raw []byte) (string, error) {
	addr := strings.TrimSpace(os.Getenv("SPAMGATE_CLAMAV_ADDRESS"))
	if addr == "" {
		return "", nil
	}
	protocol := "unix"
	if strings.HasPrefix(addr, "tcp://") {
		protocol = "tcp"
		addr = strings.TrimPrefix(addr, "tcp://")
	}
	if strings.HasPrefix(addr, "unix://") {
		addr = strings.TrimPrefix(addr, "unix://")
	}
	if protocol == "tcp" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return "", fmt.Errorf("ClamAV address must be tcp://host:port: %w", err)
		}
	} else if !strings.HasPrefix(addr, "/") {
		return "", errors.New("ClamAV UNIX socket must be an absolute path")
	}
	scanCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(scanCtx, protocol, addr)
	if err != nil {
		return "", fmt.Errorf("ClamAV connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err = conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}
	for i := 0; i < len(raw); {
		n := len(raw) - i
		if n > 32*1024 {
			n = 32 * 1024
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(n))
		if _, err = conn.Write(hdr[:]); err != nil {
			return "", err
		}
		if _, err = conn.Write(raw[i : i+n]); err != nil {
			return "", err
		}
		i += n
	}
	if _, err = conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	replyString, err := bufio.NewReaderSize(conn, 2048).ReadString(0)
	if err != nil {
		return "", fmt.Errorf("ClamAV reply: %w", err)
	}
	line := strings.TrimSpace(strings.TrimRight(replyString, "\x00"))
	switch {
	case strings.HasSuffix(line, " OK"):
		return "", nil
	case strings.HasSuffix(line, " FOUND"):
		at := strings.Index(line, ": ")
		if at < 0 {
			return "", errors.New("malformed ClamAV FOUND result")
		}
		return strings.TrimSuffix(line[at+2:], " FOUND"), nil
	default:
		return "", fmt.Errorf("ClamAV failed: %q", line)
	}
}
