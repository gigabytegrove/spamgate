package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDKIMRejectsAmbiguousSignatureTagsBeforeDNS(t *testing.T) {
	base := "v=1; a=ed25519-sha256; d=example.org; s=primary; h=from; bh=AA==; b=AA=="
	cases := []struct{ name, tags, want string }{
		{"duplicate domain", base + "; d=attacker.example", "duplicate"},
		{"duplicate selector", base + "; s=alternate", "duplicate"},
		{"duplicate signature", base + "; b=other", "duplicate"},
		{"duplicate hash", base + "; bh=BB==", "duplicate"},
		{"missing version", strings.Replace(base, "v=1; ", "", 1), "v=1"},
		{"bad version", strings.Replace(base, "v=1", "v=2", 1), "v=1"},
		{"empty interior tag", base + ";; q=dns/txt", "empty"},
		{"extra canonicalization", base + "; c=relaxed/simple/relaxed", "canonicalization"},
		{"identity outside d", base + "; i=user@another.org", "outside"},
		{"identity malformed", base + "; i=not-an-address", "identity"},
		{"invalid timestamp", base + "; t=not-a-time", "timestamp"},
		{"expiration before signing", base + "; t=200; x=100", "expiration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("From: sender@example.org\r\nDKIM-Signature: " + tc.tags + "\r\n\r\nhello\r\n")
			got := DKIMVerify(context.Background(), stubDNS{}, raw)
			if len(got) != 1 || got[0].Result != "fail" || !strings.Contains(strings.ToLower(got[0].Detail), tc.want) {
				t.Fatalf("unsafe signature not rejected as expected: %+v", got)
			}
		})
	}
}

func TestDKIMMustSignExistingFrom(t *testing.T) {
	raw := []byte("Subject: no from\r\nDKIM-Signature: v=1; a=ed25519-sha256; d=example.org; s=primary; h=from; bh=AA==; b=AA==\r\n\r\nhello\r\n")
	got := DKIMVerify(context.Background(), stubDNS{}, raw)
	if len(got) != 1 || got[0].Result != "fail" || !strings.Contains(got[0].Detail, "existing From") {
		t.Fatalf("missing signed From was not rejected: %+v", got)
	}
}

func TestDKIMRejectsAmbiguousAndUnauthorizedDNSKeys(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	p := base64.StdEncoding.EncodeToString(pub)
	base := "v=DKIM1; k=ed25519; p=" + p
	cases := []struct{ name, record string }{
		{"duplicate public key", base + "; p=" + p},
		{"duplicate key type", base + "; k=rsa"},
		{"unsupported hash", base + "; h=sha1"},
		{"not email service", base + "; s=other"},
		{"version not first", "k=ed25519; v=DKIM1; p=" + p},
		{"empty tag", base + ";;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dkimParsePublicKey([]string{tc.record}, "ed25519-sha256"); err == nil {
				t.Fatalf("accepted unsafe DKIM DNS key %s", tc.record)
			}
		})
	}
	for _, record := range []string{base, base + "; h=sha256", base + "; s=*:other", base + "; s=email"} {
		if _, err := dkimParsePublicKey([]string{record}, "ed25519-sha256"); err != nil {
			t.Fatalf("rejected valid Ed25519 key %q: %v", record, err)
		}
	}
}

func TestARCRejectsAmbiguousInstanceAndSealTags(t *testing.T) {
	wrap := func(seal, ams, aar string) []byte {
		return []byte("From: sender@example.org\r\nARC-Seal: " + seal +
			"\r\nARC-Message-Signature: " + ams +
			"\r\nARC-Authentication-Results: " + aar + "\r\n\r\nhello\r\n")
	}
	seal := "i=1; a=rsa-sha256; d=example.org; s=one; cv=none; b=fake"
	ams := "i=1; a=rsa-sha256; d=example.org; s=one; h=from; bh=fake; b=fake"
	aar := "i=1; mx.example.org; dkim=pass"
	if got := CheckARCStructure(wrap(seal, ams, aar)); got.Status != "unverified" {
		t.Fatalf("valid structural ARC unexpectedly rejected: %+v", got)
	}
	for _, raw := range [][]byte{
		wrap(seal+"; i=2", ams, aar),
		wrap(seal+"; cv=pass", ams, aar),
		wrap(seal, ams+"; i=2", aar),
		wrap(seal, ams, "i=1"),
		wrap(seal, ams, "mx.example.org; i=1"),
	} {
		if got := CheckARCStructure(raw); got.Status != "malformed" {
			t.Fatalf("ambiguous ARC set accepted: %+v", got)
		}
	}
}
