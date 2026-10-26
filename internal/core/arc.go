package core

// ARC structural diagnostics only. Cryptographic ARC-Message-Signature and
// ARC-Seal verification, chain validation, and ARC sealing are NOT implemented.
// Crucially, a structurally well-formed ARC chain is never treated as trusted
// or as equivalent to an authenticated chain (RFC 8617).

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type ARCStructure struct {
	Status    string `json:"status"` // none, malformed, unverified
	Instances int    `json:"instances"`
	Detail    string `json:"detail"`
}

func CheckARCStructure(raw []byte) ARCStructure {
	headers, _, err := dkimHeaders(raw)
	if err != nil {
		return ARCStructure{Status: "none", Detail: "Could not parse ARC headers"}
	}
	type triplet struct {
		aar, ams, seal int
		cv             string
	}
	sets := map[int]*triplet{}
	count := 0
	invalid := func(reason string) ARCStructure { return ARCStructure{Status: "malformed", Detail: reason} }
	for _, header := range headers {
		typ := 0
		switch header.name {
		case "arc-authentication-results":
			typ = 1
		case "arc-message-signature":
			typ = 2
		case "arc-seal":
			typ = 3
		default:
			continue
		}
		count++
		if count > 150 {
			return invalid("ARC exceeds 50 chain sets")
		}
		pos := bytes.IndexByte(header.raw, ':')
		if pos < 0 {
			return invalid("ARC header missing colon")
		}
		tags := dkimTags(string(header.raw[pos+1:]))
		instance, err := strconv.Atoi(strings.TrimSpace(tags["i"]))
		if err != nil || instance < 1 || instance > 50 {
			return invalid("ARC instance outside 1..50")
		}
		set := sets[instance]
		if set == nil {
			set = &triplet{}
			sets[instance] = set
		}
		switch typ {
		case 1:
			set.aar++
		case 2:
			set.ams++
		case 3:
			set.seal++
			set.cv = strings.ToLower(strings.TrimSpace(tags["cv"]))
		}
	}
	if count == 0 {
		return ARCStructure{Status: "none", Detail: "No ARC headers"}
	}
	if len(sets) > 50 {
		return invalid("ARC exceeds 50 chain sets")
	}
	for i := 1; i <= len(sets); i++ {
		set := sets[i]
		if set == nil || set.aar != 1 || set.ams != 1 || set.seal != 1 {
			return invalid(fmt.Sprintf("ARC instance %d missing or duplicated set header", i))
		}
		want := "pass"
		if i == 1 {
			want = "none"
		}
		if set.cv != want {
			return invalid(fmt.Sprintf("ARC instance %d has unexpected cv=%s", i, set.cv))
		}
	}
	return ARCStructure{Status: "unverified", Instances: len(sets), Detail: fmt.Sprintf("ARC contains %d structurally complete set(s); cryptographic verification is not implemented", len(sets))}
}
