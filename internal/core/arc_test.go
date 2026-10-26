package core

import (
	"fmt"
	"strings"
	"testing"
)

func TestARCStructureNeverAuthenticates(t *testing.T) {
	makeSet := func(i int, cv string) string {
		return fmt.Sprintf("ARC-Seal: i=%d; a=rsa-sha256; d=example.org; s=test; cv=%s; b=fake\r\nARC-Message-Signature: i=%d; a=rsa-sha256; d=example.org; s=test; bh=fake; b=fake\r\nARC-Authentication-Results: i=%d; mx.example.org; dkim=pass\r\n", i, cv, i, i)
	}
	wrap := func(s string) []byte {
		return []byte("From: sender@example.org\r\n" + s + "Subject: hi\r\n\r\nbody\r\n")
	}
	if got := CheckARCStructure(wrap("")); got.Status != "none" {
		t.Fatal(got)
	}
	if got := CheckARCStructure(wrap(makeSet(1, "none"))); got.Status != "unverified" || got.Instances != 1 {
		t.Fatal(got)
	}
	if got := CheckARCStructure(wrap(makeSet(1, "none") + makeSet(2, "pass"))); got.Status != "unverified" || got.Instances != 2 {
		t.Fatal(got)
	}
	for _, input := range []string{
		makeSet(2, "pass"),
		makeSet(1, "pass"),
		makeSet(1, "none") + makeSet(1, "none"),
		makeSet(1, "none") + strings.Replace(makeSet(2, "pass"), "cv=pass", "cv=fail", 1),
		"ARC-Seal: i=1; cv=none; b=none\r\n",
	} {
		if got := CheckARCStructure(wrap(input)); got.Status != "malformed" {
			t.Fatalf("invalid ARC accepted: %+v", got)
		}
	}
}
