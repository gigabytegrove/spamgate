package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDKIMEd25519RealSignature(t *testing.T) {
	pub, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)
	resolver := stubDNS{txt: map[string][]string{"s1._domainkey.example.org": {record}}}
	body := []byte("Hello,   there \t\r\n\r\n")
	bodySum := sha256.Sum256(dkimCanonBody(body, "relaxed"))
	line := "DKIM-Signature: v=1; a=ed25519-sha256; d=example.org; s=s1; c=relaxed/relaxed; h=from:subject; bh=" + base64.StdEncoding.EncodeToString(bodySum[:]) + "; b="
	h1 := "From: Me <me@example.org>"
	h2 := "Subject: DKIM probe"
	signed := bytes.Join([][]byte{dkimCanonHeader([]byte(h1), "relaxed"), dkimCanonHeader([]byte(h2), "relaxed"), dkimCanonHeader([]byte(line), "relaxed")}, nil)
	sum := sha256.Sum256(signed)
	line += base64.StdEncoding.EncodeToString(ed25519.Sign(secret, sum[:]))
	raw := []byte(h1 + "\r\n" + h2 + "\r\n" + line + "\r\n\r\n" + string(body))
	got := DKIMVerify(context.Background(), resolver, raw)
	if len(got) != 1 || got[0].Result != "pass" {
		t.Fatalf("expected verified signature %+v", got)
	}
	tampered := bytes.Replace(raw, []byte("Hello"), []byte("Bye!!"), 1)
	got = DKIMVerify(context.Background(), resolver, tampered)
	if len(got) != 1 || got[0].Result != "fail" || !strings.Contains(got[0].Detail, "digest") {
		t.Fatalf("expected body mismatch %+v", got)
	}
	tampered = bytes.Replace(raw, []byte("DKIM probe"), []byte("Forged probe"), 1)
	got = DKIMVerify(context.Background(), resolver, tampered)
	if len(got) != 1 || got[0].Result != "fail" || !strings.Contains(got[0].Detail, "signature") {
		t.Fatalf("expected signature mismatch %+v", got)
	}
}
func TestDKIMMissingAndMalformed(t *testing.T) {
	none := DKIMVerify(context.Background(), stubDNS{}, []byte("From: sender@example.org\r\n\r\nhello"))
	if len(none) != 1 || none[0].Result != "none" {
		t.Fatal(none)
	}
	fails := DKIMVerify(context.Background(), stubDNS{}, []byte("From: sender@example.org\r\nDKIM-Signature: d=example.org; s=default; a=rsa-sha1\r\n\r\nhello"))
	if len(fails) != 1 || fails[0].Result != "fail" {
		t.Fatal(fails)
	}
}
