package core

// RFC 9989 sections 4.10-4.10.2: bounded DNS Tree Walk for DMARC policy
// selection and relaxed identifier alignment. DNS results are cached for the
// duration of one message only; no untrusted DNS result is persisted.
import (
    "context"
    "errors"
    "fmt"
    "strings"
)

type dmarcWalkEntry struct {
    domain string
    tags map[string]string
}
type dmarcWalkResult struct {
    org string
    psd string
    records map[string]map[string]string
}
type dmarcCachedRecord struct {
    tags map[string]string
    err error
}
type dmarcDNSWalk struct {
    ctx context.Context
    resolver SPFResolver
    cache map[string]dmarcCachedRecord
    lookups int
}

// Each identifier receives at most eight DNS queries. The additional
// per-message budget limits amplification from a message with many signatures.
const maxDMARCMessageLookups = 48

func newDMARCDNSWalk(ctx context.Context, resolver SPFResolver) *dmarcDNSWalk {
    return &dmarcDNSWalk{ctx: ctx, resolver: resolver, cache: make(map[string]dmarcCachedRecord)}
}

func dmarcWalkTargets(domain string) []string {
    labels := strings.Split(domain, ".")
    targets := []string{domain}
    start := 1
    if len(labels) >= 8 {
        start = len(labels) - 7
    }
    for i := start; i < len(labels); i++ {
        target := strings.Join(labels[i:], ".")
        if target != domain {
            targets = append(targets, target)
        }
    }
    return targets
}

func (w *dmarcDNSWalk) lookup(domain string) (map[string]string, error) {
    if cached, ok := w.cache[domain]; ok {
        return cached.tags, cached.err
    }
    if w.lookups >= maxDMARCMessageLookups {
        return nil, errors.New("DMARC DNS Tree Walk per-message lookup budget exceeded")
    }
    w.lookups++
    raw, err := dmarcTXT(w.ctx, w.resolver, domain)
    var tags map[string]string
    if err == nil && raw != "" {
        tags, err = parseDMARCRecord(raw)
        if err == nil {
            switch tags["psd"] {
            case "", "y", "n", "u":
            default:
                err = fmt.Errorf("%w: invalid psd tag", errDMARCPolicy)
            }
            switch tags["t"] {
            case "", "y", "n":
            default:
                err = fmt.Errorf("%w: invalid t tag", errDMARCPolicy)
            }
            switch tags["np"] {
            case "", "none", "quarantine", "reject":
            default:
                err = fmt.Errorf("%w: invalid np tag", errDMARCPolicy)
            }
        }
    }
    w.cache[domain] = dmarcCachedRecord{tags: tags, err: err}
    return tags, err
}

func (w *dmarcDNSWalk) walk(domain string) (dmarcWalkResult, error) {
    result := dmarcWalkResult{org: domain, records: make(map[string]map[string]string)}
    if !spfValidDomain(domain) {
        return result, fmt.Errorf("%w: invalid identifier domain", errDMARCPolicy)
    }
    targets := dmarcWalkTargets(domain)
    if len(targets) > 8 {
        return result, fmt.Errorf("%w: DMARC tree exceeds eight queries", errDMARCPolicy)
    }
    var found []dmarcWalkEntry
    boundary := ""
    for i, target := range targets {
        tags, err := w.lookup(target)
        if err != nil {
            return result, err
        }
        if tags == nil {
            continue
        }
        result.records[target] = tags
        found = append(found, dmarcWalkEntry{domain: target, tags: tags})
        if tags["psd"] == "n" {
            boundary = target
            break
        }
        if tags["psd"] == "y" {
            result.psd = target
            if i > 0 {
                boundary = targets[i-1]
            }
            break
        }
    }
    if boundary != "" {
        result.org = boundary
    } else if len(found) > 0 {
        // No explicit PSD boundary: the least-specific valid record wins.
        result.org = found[len(found)-1].domain
    }
    return result, nil
}

func (w *dmarcDNSWalk) discover(domain string) (string, string, map[string]string, error) {
    result, err := w.walk(domain)
    if err != nil {
        return "", "", nil, err
    }
    if tags := result.records[domain]; tags != nil {
        return domain, result.org, tags, nil
    }
    if tags := result.records[result.org]; tags != nil {
        return result.org, result.org, tags, nil
    }
    if result.psd != "" && result.psd != domain {
        if tags := result.records[result.psd]; tags != nil {
            return result.psd, result.org, tags, nil
        }
    }
    return "", result.org, nil, nil
}

func (w *dmarcDNSWalk) aligned(used, from, fromOrg, mode string) (bool, error) {
    used = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(used)), ".")
    if used == "" || !spfValidDomain(used) {
        return false, nil
    }
    if used == from {
        return true, nil
    }
    if mode == "s" {
        return false, nil
    }
    result, err := w.walk(used)
    if err != nil {
        return false, err
    }
    return result.org != "" && result.org == fromOrg, nil
}
