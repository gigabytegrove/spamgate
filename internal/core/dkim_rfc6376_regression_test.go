package core

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// Independent RFC 6376 hash fixture: the DKIM-Signature field is the final
// signed header and MUST NOT have a trailing CRLF in the signature hash.
// Uses a folded signature as found in ordinary FedEx/Gmail outbound mail.
func TestRFC6376RSASignatureNoFinalCRLF(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := "Shipment delivered\r\n"
	digest := sha256.Sum256([]byte(body))
	bh := base64.StdEncoding.EncodeToString(digest[:])
	unsigned := "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=primary;\r\n h=from:subject; bh=" + bh + "; b="
	// Reference canonicalization written separately from implementation.
	canonical := []byte("from:Alice <alice@example.org>\r\n" +
		"subject:Delivery alert\r\n" +
		"dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=primary; h=from:subject; bh=" + bh + "; b=")
	sum := sha256.Sum256(canonical)
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(signed)
	// Insert signature data as folded physical header lines.
	folded := signature[:64] + "\r\n " + signature[64:128] + "\r\n " + signature[128:]
	raw := []byte("From: Alice <alice@example.org>\r\n" +
		"Subject: Delivery alert\r\n" + unsigned + folded + "\r\n\r\n" + body)
	txt := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	resolver := stubDNS{txt: map[string][]string{"primary._domainkey.example.org": {"v=DKIM1; k=rsa; p=" + txt}}}
	got := DKIMVerify(context.Background(), resolver, raw)
	if len(got) != 1 || got[0].Result != "pass" {
		t.Fatalf("valid RFC 6376 RSA DKIM fixture failed: %+v", got)
	}
}
