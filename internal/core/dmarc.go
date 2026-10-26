package core

// Exact-domain DMARC evaluation. This deliberately does not claim full RFC 7489
// parity: public-suffix-aware organizational-domain policy discovery and PSD
// DMARC require a maintained public suffix implementation before enforcement.

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"
)

type DMARCResult struct{ Result, Domain, Policy, Detail string }

func dmarcAligned(used, from, mode string) bool {
	used = strings.TrimSuffix(strings.ToLower(used), ".")
	from = strings.TrimSuffix(strings.ToLower(from), ".")
	if used == "" || from == "" {
		return false
	}
	if used == from {
		return true
	}
	if mode == "s" {
		return false
	}
	// Relaxed alignment for a policy located at the actual From domain: a
	// subdomain authenticated by its parent satisfies alignment. Avoid
	// extending alignment to sibling tenants without a public suffix list.
	return strings.HasSuffix(used, "."+from)
}
func DMARCCheck(ctx context.Context, resolver SPFResolver, headerFrom string, spf SPFResult, dkim []DKIMResult) DMARCResult {
	result := DMARCResult{Result: "none"}
	addresses, err := mail.ParseAddressList(headerFrom)
	if err != nil || len(addresses) != 1 {
		result.Detail = "DMARC requires exactly one valid RFC 5322 From identity"
		return result
	}
	address := addresses[0].Address
	p := strings.LastIndex(address, "@")
	if p < 0 {
		return result
	}
	domain := strings.ToLower(strings.TrimSuffix(address[p+1:], "."))
	result.Domain = domain
	if !isSubdomain(domain) {
		result.Detail = "Invalid From domain"
		return result
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txts, err := resolver.LookupTXT(dnsCtx, "_dmarc."+domain)
	if err != nil {
		result.Detail = "DMARC policy TXT lookup: " + err.Error()
		return result
	}
	var record string
	for _, txt := range txts {
		if strings.EqualFold(dkimTags(txt)["v"], "DMARC1") {
			if record != "" {
				result.Result = "permerror"
				result.Detail = "Multiple DMARC policies"
				return result
			}
			record = txt
		}
	}
	if record == "" {
		result.Detail = "No exact-domain DMARC policy; organizational-domain fallback not supported"
		return result
	}
	tags := dkimTags(record)
	policy := strings.ToLower(tags["p"])
	if policy != "none" && policy != "quarantine" && policy != "reject" {
		result.Result = "permerror"
		result.Detail = "Invalid DMARC policy"
		return result
	}
	for _, k := range []string{"adkim", "aspf"} {
		if tags[k] != "" && tags[k] != "r" && tags[k] != "s" {
			result.Result = "permerror"
			result.Detail = "Invalid DMARC alignment mode"
			return result
		}
	}
	result.Policy = policy
	if spf.Result == "pass" && dmarcAligned(spf.Domain, domain, tags["aspf"]) {
		result.Result = "pass"
		result.Detail = "SPF authenticated the RFC 5322 From domain"
		return result
	}
	for _, sig := range dkim {
		if sig.Result == "pass" && dmarcAligned(sig.Domain, domain, tags["adkim"]) {
			result.Result = "pass"
			result.Detail = "DKIM aligned with the RFC 5322 From domain"
			return result
		}
	}
	result.Result = "fail"
	result.Detail = fmt.Sprintf("DMARC authentication failed (exact-domain p=%s; unaligned SPF/DKIM)", policy)
	return result
}
