package core

// ARC chain verification (RFC 8617 §5.2): validates the newest AMS and every
// ARC-Seal's cryptographic chain. Valid ARC means tamper evidence only; no
// intermediary is automatically trusted and ARC does not override DMARC.
import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type ARCValidation struct {
	Status    string `json:"status"` // none, malformed, pass, fail, temperror
	Instances int    `json:"instances"`
	Detail    string `json:"detail"`
}

type arcSet struct{ aar, ams, seal int }

func ValidateARC(ctx context.Context, resolver SPFResolver, raw []byte) ARCValidation {
	// One global budget includes all seal DNS operations; a hostile 50-set ARC
	// chain must not create 50 sequential remote lookup timeouts.
	budgetCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = budgetCtx
	structural := CheckARCStructure(raw)
	res := ARCValidation{Status: structural.Status, Instances: structural.Instances, Detail: structural.Detail}
	if structural.Status == "none" || structural.Status == "malformed" {
		return res
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	headers, body, err := dkimHeaders(raw)
	if err != nil {
		res.Status = "malformed"
		res.Detail = err.Error()
		return res
	}
	sets := make([]arcSet, structural.Instances+1)
	for i := range sets {
		sets[i] = arcSet{-1, -1, -1}
	}
	for index, h := range headers {
		switch h.name {
		case "arc-authentication-results", "arc-message-signature", "arc-seal":
			fields := dkimTags(string(h.raw[bytes.IndexByte(h.raw, ':')+1:]))
			n, err := strconv.Atoi(fields["i"])
			if err != nil || n < 1 || n >= len(sets) {
				res.Status = "malformed"
				res.Detail = "ARC instance out of range"
				return res
			}
			switch h.name {
			case "arc-authentication-results":
				sets[n].aar = index
			case "arc-message-signature":
				sets[n].ams = index
			case "arc-seal":
				sets[n].seal = index
			}
		}
	}
	latest := sets[structural.Instances]
	if latest.ams < 0 {
		res.Status = "malformed"
		res.Detail = "ARC newest AMS missing"
		return res
	}
	// The newest AMS must sign the present message; older AMS signatures
	// can become invalid after a legitimate later forwarder's modifications.
	amsHeader := headers[latest.ams]
	amsTags := dkimTags(string(amsHeader.raw[bytes.IndexByte(amsHeader.raw, ':')+1:]))
	for _, name := range strings.Split(strings.ToLower(amsTags["h"]), ":") {
		if strings.HasPrefix(strings.TrimSpace(name), "arc-") || strings.EqualFold(strings.TrimSpace(name), "authentication-results") {
			res.Status = "fail"
			res.Detail = "AMS signed prohibited ARC/Authentication-Results header"
			return res
		}
	}
	ams := dkimVerifyOne(ctx, resolver, headers, body, latest.ams)
	if ams.Result != "pass" {
		res.Status = "fail"
		if ams.Result == "temperror" {
			res.Status = "temperror"
		}
		res.Detail = "Most recent ARC-Message-Signature: " + ams.Detail
		return res
	}
	// Verify each ARC-Seal from oldest to newest, covering its entire chain
	// up to and including its own ARC set. Headers are always relaxed.
	for n := 1; n < len(sets); n++ {
		var signed []byte
		for j := 1; j <= n; j++ {
			set := sets[j]
			if set.aar < 0 || set.ams < 0 || set.seal < 0 {
				res.Status = "malformed"
				res.Detail = "Incomplete ARC set"
				return res
			}
			signed = append(signed, dkimCanonHeader(headers[set.aar].raw, "relaxed")...)
			signed = append(signed, dkimCanonHeader(headers[set.ams].raw, "relaxed")...)
			seal := headers[set.seal].raw
			if j == n {
				blank, err := dkimEmptySignatureValue(seal)
				if err != nil {
					res.Status = "fail"
					res.Detail = "Cannot canonicalize ARC-Seal"
					return res
				}
				canonical := dkimCanonHeader(blank, "relaxed")
				if len(canonical) < 2 {
					res.Status = "fail"
					res.Detail = "Invalid ARC-Seal canonicalization"
					return res
				}
				signed = append(signed, canonical[:len(canonical)-2]...)
			} else {
				signed = append(signed, dkimCanonHeader(seal, "relaxed")...)
			}
		}
		seal := headers[sets[n].seal].raw
		tags := dkimTags(string(seal[bytes.IndexByte(seal, ':')+1:]))
		if tags["h"] != "" || tags["bh"] != "" || tags["c"] != "" {
			res.Status = "fail"
			res.Detail = "ARC-Seal contains prohibited DKIM tags"
			return res
		}
		domain, selector := strings.ToLower(tags["d"]), strings.ToLower(tags["s"])
		if !isSubdomain(domain) || selector == "" || strings.ContainsAny(selector, " /:@\\\r\n\t") {
			res.Status = "fail"
			res.Detail = "Invalid ARC-Seal signer"
			return res
		}
		alg := strings.ToLower(tags["a"])
		if alg != "rsa-sha256" && alg != "ed25519-sha256" {
			res.Status = "fail"
			res.Detail = "Unsupported ARC-Seal signing algorithm"
			return res
		}
		sig, err := base64.StdEncoding.DecodeString(dkimCompact(tags["b"]))
		if err != nil || len(sig) == 0 {
			res.Status = "fail"
			res.Detail = "Malformed ARC-Seal signature"
			return res
		}
		dnsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		txts, err := resolver.LookupTXT(dnsCtx, selector+"._domainkey."+domain)
		cancel()
		if err != nil {
			res.Status = "temperror"
			res.Detail = fmt.Sprintf("ARC-Seal instance %d DNS lookup: %v", n, err)
			return res
		}
		key, err := dkimParsePublicKey(txts, alg)
		if err != nil {
			res.Status = "fail"
			res.Detail = fmt.Sprintf("ARC-Seal instance %d invalid key: %v", n, err)
			return res
		}
		hash := sha256.Sum256(signed)
		switch k := key.(type) {
		case *rsa.PublicKey:
			err = rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], sig)
		case ed25519.PublicKey:
			if !ed25519.Verify(k, hash[:], sig) {
				err = errors.New("signature mismatch")
			}
		default:
			err = errors.New("unsupported ARC-Seal public key")
		}
		if err != nil {
			res.Status = "fail"
			res.Detail = fmt.Sprintf("ARC-Seal instance %d verification: %v", n, err)
			return res
		}
	}
	res.Status = "pass"
	res.Detail = fmt.Sprintf("Verified latest ARC-Message-Signature and all %d ARC-Seal signatures; sender trust is not inferred", len(sets)-1)
	return res
}
