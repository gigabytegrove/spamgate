package core

// DKIM verification for rsa-sha256 and ed25519-sha256 signatures (RFC 6376,
// RFC 8463). The public key comes from DNS, not from message-supplied data.
// Verification never authenticates the SMTP envelope or determines DMARC.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DKIMResult struct{ Result, Domain, Selector, Detail string }
type dkimHeader struct {
	name string
	raw  []byte
}

var dkimFolding = regexp.MustCompile(`\r\n[ \t]+`)
var dkimWSP = regexp.MustCompile(`[ \t]+`)

func dkimHeaders(raw []byte) ([]dkimHeader, []byte, error) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, nil, errors.New("DKIM requires CRLF header delimiters")
	}
	rawHeader := raw[:idx]
	lines := bytes.Split(rawHeader, []byte("\r\n"))
	var headers []dkimHeader
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(headers) == 0 {
				return nil, nil, errors.New("orphan header folding")
			}
			n := len(headers) - 1
			headers[n].raw = append(headers[n].raw, []byte("\r\n")...)
			headers[n].raw = append(headers[n].raw, line...)
		} else {
			p := bytes.IndexByte(line, ':')
			if p <= 0 {
				return nil, nil, errors.New("invalid DKIM message header")
			}
			name := strings.ToLower(string(line[:p]))
			headers = append(headers, dkimHeader{name: name, raw: append([]byte(nil), line...)})
		}
	}
	return headers, raw[idx+4:], nil
}
func dkimTags(input string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(input, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		tags[k] = strings.TrimSpace(v)
	}
	return tags
}
func dkimCompact(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}
func dkimCanonHeader(raw []byte, style string) []byte {
	if style != "relaxed" {
		return append(append([]byte(nil), raw...), '\r', '\n')
	}
	n := bytes.IndexByte(raw, ':')
	if n < 0 {
		return nil
	}
	name := bytes.ToLower(raw[:n])
	value := dkimFolding.ReplaceAll(raw[n+1:], []byte(" "))
	value = dkimWSP.ReplaceAll(bytes.TrimSpace(value), []byte(" "))
	result := make([]byte, 0, len(name)+len(value)+3)
	result = append(result, name...)
	result = append(result, ':')
	result = append(result, value...)
	return append(result, '\r', '\n')
}
func dkimCanonBody(body []byte, style string) []byte {
	// SMTP transports use CRLF. Normalize standalone LF for tolerant local input;
	// malformed bare CR remains literal (and will normally fail the digest).
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(body, []byte{'\n'})
	var out [][]byte
	for _, line := range lines {
		if style == "relaxed" {
			line = bytes.TrimRight(line, " \t")
			line = dkimWSP.ReplaceAll(line, []byte(" "))
		}
		out = append(out, line)
	}
	for len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	var result []byte
	for _, line := range out {
		result = append(result, line...)
		result = append(result, '\r', '\n')
	}
	if len(result) == 0 {
		return []byte("\r\n")
	}
	return result
}
func dkimEmptySignatureValue(raw []byte) ([]byte, error) {
	idx := bytes.IndexByte(raw, ':')
	if idx < 0 {
		return nil, errors.New("missing DKIM colon")
	}
	value := raw[idx+1:]
	// Locate precisely the b tag, not bh, and retain all surrounding bytes.
	tagStart := -1
	for i := 0; i < len(value); {
		for i < len(value) && (value[i] == ' ' || value[i] == '\t' || value[i] == ';' || value[i] == '\r' || value[i] == '\n') {
			i++
		}
		start := i
		for i < len(value) && value[i] != '=' && value[i] != ';' {
			i++
		}
		if i >= len(value) || value[i] != '=' {
			if i < len(value) {
				i++
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(value[start:i])), "b") {
			tagStart = i + 1
			break
		}
		for i < len(value) && value[i] != ';' {
			i++
		}
	}
	if tagStart < 0 {
		return nil, errors.New("missing DKIM b tag")
	}
	end := tagStart
	for end < len(value) && value[end] != ';' {
		end++
	}
	result := make([]byte, 0, len(raw)-(end-tagStart))
	result = append(result, raw[:idx+1+tagStart]...)
	result = append(result, raw[idx+1+end:]...)
	return result, nil
}
func dkimParsePublicKey(txts []string, algorithm string) (crypto.PublicKey, error) {
	var record string
	for _, txt := range txts {
		parts := dkimTags(txt)
		if parts["p"] != "" || strings.EqualFold(parts["v"], "DKIM1") {
			if record != "" {
				return nil, errors.New("multiple DKIM public keys")
			}
			record = txt
		}
	}
	if record == "" {
		return nil, errors.New("no DKIM key record")
	}
	tags := dkimTags(record)
	if tags["v"] != "" && !strings.EqualFold(tags["v"], "DKIM1") {
		return nil, errors.New("unknown DKIM key version")
	}
	if tags["p"] == "" {
		return nil, errors.New("DKIM key revoked or missing")
	}
	data, err := base64.StdEncoding.DecodeString(dkimCompact(tags["p"]))
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(tags["k"])
	if typ == "" {
		typ = "rsa"
	}
	switch algorithm {
	case "rsa-sha256":
		if typ != "rsa" {
			return nil, errors.New("signature/key algorithm mismatch")
		}
		var pub any
		pub, err = x509.ParsePKCS1PublicKey(data)
		if err != nil {
			pub, err = x509.ParsePKIXPublicKey(data)
		}
		if err != nil {
			return nil, err
		}
		key, ok := pub.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 1024 {
			return nil, errors.New("DKIM RSA key must be at least 1024 bits")
		}
		return key, nil
	case "ed25519-sha256":
		if typ != "ed25519" || len(data) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 DKIM key")
		}
		return ed25519.PublicKey(data), nil
	default:
		return nil, errors.New("unsupported DKIM signing algorithm")
	}
}
func dkimVerifyOne(ctx context.Context, resolver SPFResolver, headers []dkimHeader, body []byte, index int) DKIMResult {
	sig := headers[index]
	tags := dkimTags(string(sig.raw[bytes.IndexByte(sig.raw, ':')+1:]))
	domain := strings.ToLower(tags["d"])
	selector := strings.ToLower(tags["s"])
	result := DKIMResult{Result: "fail", Domain: domain, Selector: selector}
	fail := func(reason string) DKIMResult { result.Detail = reason; return result }
	if !isSubdomain(domain) || selector == "" || strings.ContainsAny(selector, "/ :@\\\r\n\t") {
		return fail("Malformed DKIM domain or selector")
	}
	algorithm := strings.ToLower(tags["a"])
	if algorithm != "rsa-sha256" && algorithm != "ed25519-sha256" {
		return fail("Unsupported or insecure DKIM signing algorithm")
	}
	bodyStyle, headerStyle := "simple", "simple"
	if tags["c"] != "" {
		parts := strings.Split(tags["c"], "/")
		headerStyle = parts[0]
		if len(parts) > 1 {
			bodyStyle = parts[1]
		}
	}
	if (headerStyle != "simple" && headerStyle != "relaxed") || (bodyStyle != "simple" && bodyStyle != "relaxed") {
		return fail("Unsupported DKIM canonicalization")
	}
	canonBody := dkimCanonBody(body, bodyStyle)
	if length := tags["l"]; length != "" {
		n, err := strconv.Atoi(length)
		if err != nil || n < 0 || n > len(canonBody) {
			return fail("Invalid DKIM body-length limit")
		}
		canonBody = canonBody[:n]
	}
	claimed, err := base64.StdEncoding.DecodeString(dkimCompact(tags["bh"]))
	if err != nil {
		return fail("Invalid DKIM body hash encoding")
	}
	sum := sha256.Sum256(canonBody)
	if !bytes.Equal(sum[:], claimed) {
		return fail("DKIM body digest mismatch")
	}
	signed := strings.Split(strings.ToLower(tags["h"]), ":")
	signedFrom := false
	used := map[int]bool{}
	var headerData []byte
	for _, name := range signed {
		name = strings.TrimSpace(name)
		if name == "from" {
			signedFrom = true
		}
		if name == "" {
			return fail("Invalid empty signed header name")
		}
		found := -1
		for i := len(headers) - 1; i >= 0; i-- {
			if headers[i].name == name && !used[i] {
				found = i
				break
			}
		}
		if found < 0 {
			continue
		} // permitted header oversigning
		used[found] = true
		headerData = append(headerData, dkimCanonHeader(headers[found].raw, headerStyle)...)
	}
	if !signedFrom {
		return fail("DKIM must sign From header")
	}
	blank, err := dkimEmptySignatureValue(sig.raw)
	if err != nil {
		return fail(err.Error())
	}
	headerData = append(headerData, dkimCanonHeader(blank, headerStyle)...)
	signature, err := base64.StdEncoding.DecodeString(dkimCompact(tags["b"]))
	if err != nil {
		return fail("Invalid DKIM signature encoding")
	}
	query := selector + "._domainkey." + domain
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txts, err := resolver.LookupTXT(dnsCtx, query)
	if err != nil {
		result.Result = spfDNSFailure(err)
		return fail("DKIM DNS key lookup failed: " + err.Error())
	}
	pub, err := dkimParsePublicKey(txts, algorithm)
	if err != nil {
		return fail(err.Error())
	}
	digest := sha256.Sum256(headerData)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature)
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest[:], signature) {
			err = errors.New("Ed25519 DKIM signature mismatch")
		}
	}
	if err != nil {
		return fail("DKIM signature verification failed: " + err.Error())
	}
	if expired := tags["x"]; expired != "" {
		x, err := strconv.ParseInt(expired, 10, 64)
		if err != nil || time.Now().Unix() > x {
			return fail("DKIM signature expired")
		}
	}
	result.Result = "pass"
	result.Detail = fmt.Sprintf("DKIM signature verified: %s._domainkey.%s (%s)", selector, domain, algorithm)
	if tags["l"] != "" {
		result.Detail += "; body length is explicitly limited"
	}
	return result
}
func DKIMVerify(ctx context.Context, resolver SPFResolver, raw []byte) []DKIMResult {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	headers, body, err := dkimHeaders(raw)
	if err != nil {
		return []DKIMResult{{Result: "none", Detail: err.Error()}}
	}
	var results []DKIMResult
	for i, h := range headers {
		if h.name == "dkim-signature" {
			if len(results) >= 10 {
				break
			}
			results = append(results, dkimVerifyOne(ctx, resolver, headers, body, i))
		}
	}
	if len(results) == 0 {
		return []DKIMResult{{Result: "none", Detail: "No DKIM-Signature header"}}
	}
	return results
}
