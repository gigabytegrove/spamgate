package core

// Optional MIME/ZIP metadata inspection. All work is bounded. This is not a
// replacement for antivirus, dynamic analysis or an archive decompression
// sandbox. No attachment is executed or written to disk.
import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

type AttachmentFinding struct {
	Symbol string
	Detail string
	Score  float64
}

func riskyFilename(name string) bool {
	name = strings.ToLower(name)
	for _, ext := range []string{".exe", ".scr", ".com", ".msi", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".jar", ".lnk", ".iso", ".docm", ".xlsm", ".xll"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
func attachmentPayload(raw []byte, transfer string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(transfer)) {
	case "base64":
		// Limit BEFORE decoding and handle whitespace without unbounded buffers.
		if len(raw) > 5<<20 {
			return nil, fmt.Errorf("encoded MIME part exceeds limit")
		}
		clean := make([]byte, 0, len(raw))
		for _, b := range raw {
			if b != ' ' && b != '\r' && b != '\n' && b != '\t' {
				clean = append(clean, b)
			}
		}
		out, err := base64.StdEncoding.DecodeString(string(clean))
		if err != nil {
			return nil, err
		}
		return out, nil
	case "quoted-printable":
		out, err := io.ReadAll(io.LimitReader(quotedPrintableReader(bytes.NewReader(raw)), (4<<20)+1))
		if err != nil { return nil, err }
		if len(out) > 4<<20 { return nil, fmt.Errorf("decoded MIME part exceeds 4 MiB limit") }
		return out, nil
	default:
		return raw, nil
	}
}

func InspectMIMEAttachments(raw []byte) ([]AttachmentFinding, error) {
	if len(raw) > 10<<20 {
		return nil, fmt.Errorf("message too large")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(msg.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	found := []AttachmentFinding{}
	appendFinding := func(symbol, detail string, score float64) {
		if len(found) >= 20 {
			return
		}
		if len(detail) > 180 {
			detail = detail[:180]
		}
		found = append(found, AttachmentFinding{Symbol: symbol, Detail: detail, Score: score})
	}
	count := 0
	var inspect func(mail.Header, []byte, int)
	inspect = func(h mail.Header, data []byte, depth int) {
		if depth > 6 || count >= 60 {
			appendFinding("MIME_LIMIT", "Attachment inspection depth or part count exceeded", 0)
			return
		}
		count++
		media, params, err := mime.ParseMediaType(h.Get("Content-Type"))
		if err != nil {
			media = "application/octet-stream"
		}
		if strings.HasPrefix(media, "multipart/") {
			if params["boundary"] == "" {
				appendFinding("MIME_MALFORMED", "Multipart boundary missing", 0)
				return
			}
			mr := multipart.NewReader(bytes.NewReader(data), params["boundary"])
			for count < 60 {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					appendFinding("MIME_MALFORMED", "Multipart section could not be parsed", 0)
					break
				}
				chunk, err := io.ReadAll(io.LimitReader(part, 5<<20+1))
				part.Close()
				if err != nil || len(chunk) > 5<<20 {
					appendFinding("MIME_LIMIT", "Attachment exceeds 5 MiB inspection limit", 0)
					continue
				}
				inspect(mail.Header(part.Header), chunk, depth+1)
			}
			return
		}
		name := params["name"]
		disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
		if dparams["filename"] != "" {
			name = dparams["filename"]
		}
		if name == "" && disp != "attachment" && media != "application/octet-stream" {
			return
		}
		if name == "" {
			name = "unnamed attachment"
		}
		payload, err := attachmentPayload(data, h.Get("Content-Transfer-Encoding"))
		if err != nil || len(payload) > 5<<20 {
			appendFinding("MIME_UNREADABLE", "Attachment cannot be decoded safely: "+name, 0)
			return
		}
		// Compare actual bytes, not filename or claimed Content-Type alone.
		if bytes.HasPrefix(payload, []byte("MZ")) || bytes.HasPrefix(payload, []byte{0x7f, 'E', 'L', 'F'}) {
			appendFinding("ATTACHMENT_EXECUTABLE_CONTENT", "Executable file signature in: "+name, 6)
		}
		if bytes.HasPrefix(payload, []byte("PK\x03\x04")) {
			inspectZIPAttachment(payload, name, appendFinding)
		}
	}
	inspect(msg.Header, body, 0)
	return found, nil
}
