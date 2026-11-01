package core

import "strings"

// Legacy PSL alignment assertion retained solely for historical regression
// fixtures. Runtime DMARCCheck uses dmarcDNSWalk.aligned (RFC 9989), not this
// PSL-based helper. Do not use this helper for mail enforcement.
func dmarcAligned(used, from, mode string) bool {
    used = strings.TrimSuffix(strings.ToLower(used), ".")
    from = strings.TrimSuffix(strings.ToLower(from), ".")
    if used == "" || from == "" { return false }
    if used == from { return true }
    if mode == "s" { return false }
    org := organizationalDomain(from)
    return org != "" && org == organizationalDomain(used)
}
