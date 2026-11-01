package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
)

var (
	errSMTPDataTooLarge = errors.New("SMTP DATA exceeds maximum message size")
	errSMTPDataMalformed = errors.New("malformed SMTP DATA wire framing")
	errSMTPCommandMalformed = errors.New("malformed SMTP command wire framing")
)

// readSMTPCommand requires an RFC 5321 CRLF-terminated command, bounded to
// 512 octets including CRLF. A malformed command is fatal to the connection:
// continuing after a framing error could interpret message data as commands.
func readSMTPCommand(reader *bufio.Reader) (string, error) {
	line, err := readLineLimited(reader, 512)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errSMTPCommandMalformed, err)
	}
	if len(line) < 2 || !bytes.HasSuffix(line, []byte("\r\n")) {
		return "", fmt.Errorf("%w: command must end with CRLF", errSMTPCommandMalformed)
	}
	for _, b := range line[:len(line)-2] {
		if b == 0 || b == '\r' || (b < 32 && b != '\t') || b == 127 {
			return "", fmt.Errorf("%w: invalid command control octet", errSMTPCommandMalformed)
		}
	}
	return string(line[:len(line)-2]), nil
}

// readSMTPData validates the wire before scanning or durable acceptance.
// Every DATA line is at most 1000 octets including CRLF and transparency
// dots. Only an exact <CRLF>.<CRLF> terminates DATA. Invalid framing closes
// the connection; an oversized but correctly framed message is drained to
// the terminator so the SMTP session can safely accept another transaction.
func readSMTPData(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	if maxBytes < 0 {
		return nil, errSMTPDataTooLarge
	}
	var raw bytes.Buffer
	tooLarge := false
	for {
		line, err := readLineLimited(reader, 1000)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errSMTPDataMalformed, err)
		}
		if len(line) < 2 || !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, fmt.Errorf("%w: DATA line must end with CRLF", errSMTPDataMalformed)
		}
		if bytes.Equal(line, []byte(".\r\n")) {
			if tooLarge {
				return nil, errSMTPDataTooLarge
			}
			return raw.Bytes(), nil
		}
		if line[0] == '.' {
			if len(line) < 4 || line[1] != '.' {
				return nil, fmt.Errorf("%w: invalid dot transparency", errSMTPDataMalformed)
			}
			line = line[1:]
		}
		body := line[:len(line)-2]
		if bytes.IndexByte(body, 0) >= 0 || bytes.IndexByte(body, '\r') >= 0 {
			return nil, fmt.Errorf("%w: NUL or bare CR in DATA", errSMTPDataMalformed)
		}
		if !tooLarge {
			if len(line) > maxBytes-raw.Len() {
				tooLarge = true
			} else {
				_, _ = raw.Write(line)
			}
		}
	}
}
