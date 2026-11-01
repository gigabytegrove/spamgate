package core

// RFC 9989 §3.2.13 and §4.7 distinguish NXDOMAIN from NOERROR/NODATA.
// The standard Go net.Resolver interface does not expose DNS response codes,
// so callers with an authoritative DNS response-code backend may implement
// DMARCNameStatusResolver. An absent backend cannot justify np enforcement.

import (
	"context"
	"errors"
	"fmt"
)

var errDMARCNameStatusUnavailable = errors.New("DNS NXDOMAIN status unavailable; authoritative response-code resolver required")

// DMARCNameStatusResolver returns true only for an actual NXDOMAIN response
// for the exact Author Domain, not for a missing A/TXT/MX record. DNS
// timeouts, SERVFAIL, REFUSED and ambiguous responses must return an error.
// An implementation must respect ctx and must not treat a wildcard NODATA
// answer as NXDOMAIN.
type DMARCNameStatusResolver interface {
	DMARCNameNXDOMAIN(ctx context.Context, authorDomain string) (bool, error)
}

func (w *dmarcDNSWalk) inheritedNonexistentPolicy(domain, existingPolicy, nonexistentPolicy string) (string, error) {
	if nonexistentPolicy == "" || nonexistentPolicy == existingPolicy {
		return existingPolicy, nil
	}
	backend, ok := w.resolver.(DMARCNameStatusResolver)
	if !ok {
		return "", errDMARCNameStatusUnavailable
	}
	if err := w.ctx.Err(); err != nil {
		return "", err
	}
	nx, err := backend.DMARCNameNXDOMAIN(w.ctx, domain)
	if err != nil {
		return "", fmt.Errorf("Author Domain DNS existence check: %w", err)
	}
	if nx {
		return nonexistentPolicy, nil
	}
	return existingPolicy, nil
}
