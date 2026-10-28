package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func signedARCFixture(t *testing.T) ([]byte, SPFResolver) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(data []byte) string {
		digest := sha256.Sum256(data)
		sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	body := "ARC fixture contents\r\n"
	hash := sha256.Sum256([]byte(body))
	from := "From: alice@example.org"
	subject := "Subject: ARC fixture"
	aar := "ARC-Authentication-Results: i=1; relay.example.org; dkim=pass header.d=example.org"
	amsEmpty := "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=seal; h=from:subject; bh=" + base64.StdEncoding.EncodeToString(hash[:]) + "; b="
	amsSigned := []byte("from:alice@example.org\r\nsubject:ARC fixture\r\n" + strings.ToLower("ARC-Message-Signature") + ":" + strings.TrimPrefix(amsEmpty, "ARC-Message-Signature: "))
	// canonicalization directly reflects the RFC fixture's relaxed form.
	ams := amsEmpty + sign(amsSigned)
	asEmpty := "ARC-Seal: i=1; a=rsa-sha256; d=example.org; s=seal; cv=none; b="
	sealHeaderBytes := append(dkimCanonHeader([]byte(aar), "relaxed"), dkimCanonHeader([]byte(ams), "relaxed")...)
	sealHeaderBytes = append(sealHeaderBytes, dkimCanonHeader([]byte(asEmpty), "relaxed")[:len(dkimCanonHeader([]byte(asEmpty), "relaxed"))-2]...)
	seal := asEmpty + sign(sealHeaderBytes)
	raw := []byte(from + "\r\n" + subject + "\r\n" + aar + "\r\n" + ams + "\r\n" + seal + "\r\n\r\n" + body)
	public := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	return raw, stubDNS{txt: map[string][]string{"seal._domainkey.example.org": {"v=DKIM1; k=rsa; p=" + public}}}
}
func TestARCCryptoVerifiesIndependentRSAFixture(t *testing.T) {
	raw, dns := signedARCFixture(t)
	got := ValidateARC(context.Background(), dns, raw)
	if got.Status != "pass" {
		t.Fatalf("valid chain failed: %+v", got)
	}
	modified := bytes.Replace(raw, []byte("ARC fixture contents"), []byte("ARC fixture tampered"), 1)
	if res := ValidateARC(context.Background(), dns, modified); res.Status != "fail" {
		t.Fatalf("tampered body accepted: %+v", res)
	}
	modified = bytes.Replace(raw, []byte("dkim=pass header.d=example.org"), []byte("dkim=fail header.d=example.org"), 1)
	if res := ValidateARC(context.Background(), dns, modified); res.Status != "fail" {
		t.Fatalf("tampered ARC authentication-results accepted: %+v", res)
	}
}
func zippedFile(t *testing.T, filename string, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, e := z.Create(filename)
	if e != nil {
		t.Fatal(e)
	}
	w.Write(body)
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func attachmentEmail(encoded string) []byte {
	return []byte("From: sender@example.org\r\nSubject: Report\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=report.zip\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n--b--\r\n")
}
func TestAttachmentInspectionBoundedAndOptIn(t *testing.T) {
	dangerous := zippedFile(t, "invoice.pdf.exe", []byte("MZfake"))
	raw := attachmentEmail(base64.StdEncoding.EncodeToString(dangerous))
	got, e := InspectMIMEAttachments(raw)
	if e != nil {
		t.Fatal(e)
	}
	matched := false
	for _, f := range got {
		if f.Symbol == "ARCHIVE_RISKY_MEMBER" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("archive member not found: %+v", got)
	}
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	without, e := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: raw})
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range without.Findings {
		if f.Symbol == "ARCHIVE_RISKY_MEMBER" {
			t.Fatal("feature affected default-disabled scanning")
		}
	}
	if e := st.UpdateConfig(func(c *Config) error { c.Settings.AttachmentInspection = true; return nil }); e != nil {
		t.Fatal(e)
	}
	with, e := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: raw})
	if e != nil {
		t.Fatal(e)
	}
	if with.Score <= without.Score {
		t.Fatalf("inspected content did not affect scoring: %f <= %f", with.Score, without.Score)
	}
	huge := attachmentEmail(strings.Repeat("A", 5<<20+10))
	result, err := InspectMIMEAttachments(huge)
	if err == nil {
		foundLimit := false
		for _, item := range result {
			if item.Symbol == "MIME_LIMIT" {
				foundLimit = true
			}
		}
		if !foundLimit {
			t.Fatalf("oversized attachment failed to generate a bounded inspection result: %+v", result)
		}
	}
}
func TestExternalFuzzyUsesOnlyFingerprintAndFailsOpen(t *testing.T) {
	text := "This is a long and unique example of the email body that will have more than eighteen different word tokens to make the fuzzy fingerprint work correctly in our tests and prevent accidental empty input"
	raw := []byte("From: sender@example.org\r\nSubject: newsletter\r\n\r\n" + text)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing auth header")
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 2048))
		if bytes.Contains(b, []byte("newsletter")) || bytes.Contains(b, []byte("sender@example.org")) || bytes.Contains(b, []byte("unique example")) {
			t.Errorf("raw content leaked to provider: %s", b)
		}
		var v map[string]any
		if json.Unmarshal(b, &v) != nil || v["algorithm"] != "spamgate-simhash64-v1" {
			t.Errorf("bad request: %s", b)
		}
		fmt.Fprint(w, `{"label":"spam","confidence":0.99,"samples":80,"provider":"test"}`)
	}))
	defer srv.Close()
	t.Setenv("SPAMGATE_FUZZY_URL", srv.URL)
	t.Setenv("SPAMGATE_FUZZY_TOKEN", "test-token")
	// Inject TLS trust in tests using an explicit cert pool; never skip verify.
	original := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = original }()
	got, err := CheckRemoteFuzzy(context.Background(), raw)
	if err != nil || got.Label != "spam" {
		t.Fatalf("fuzzy test failed: %+v, %v", got, err)
	}
	t.Setenv("SPAMGATE_FUZZY_URL", "http://example.org")
	if _, err = CheckRemoteFuzzy(context.Background(), raw); err == nil {
		t.Fatal("insecure provider accepted")
	}
}
func TestRecipientPolicyScopedAndSafeForMultipleRecipients(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	e = st.UpdateConfig(func(c *Config) error {
		c.RecipientPolicies = []RecipientPolicy{{Mailbox: "recipient@example.org", TagThreshold: 1, QuarantineThreshold: 2, RejectThreshold: 3}}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte("From: x@example.org\r\nTo: recipient@example.org\r\nSubject: test\r\n\r\nbody")
	single, e := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: raw, Recipients: []string{"recipient@example.org"}})
	if e != nil {
		t.Fatal(e)
	}
	if single.Scoring.RejectThreshold != 3 {
		t.Fatalf("mailbox override not applied: %+v", single.Scoring)
	}
	multi, e := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: raw, Recipients: []string{"recipient@example.org", "other@example.org"}})
	if e != nil {
		t.Fatal(e)
	}
	if multi.Scoring.RejectThreshold != 20 {
		t.Fatalf("shared transaction got mailbox-only policy: %+v", multi.Scoring)
	}
	if e = st.UpdateConfig(func(c *Config) error {
		c.RecipientPolicies = append(c.RecipientPolicies, c.RecipientPolicies[0])
		return nil
	}); e == nil {
		t.Fatal("duplicate policy persisted")
	}
}
