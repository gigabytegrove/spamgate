package core

// phishingSameOrganization compares browser-visible URL claims against the
// actual destination using the bundled/overridden Public Suffix List.
//
// A simple suffix comparison is unsafe for multi-tenant public suffixes:
// alice.github.io and bob.github.io are different organizations, even though
// both end in github.io. Conversely, support.example.com and
// login.example.com are ordinary sibling hosts and should not by themselves
// generate a scored phishing mismatch.
//
// Both inputs have already passed ValidReputationDomain. Exact equality is
// still allowed for public-suffix hosts without a registrable owner.
func phishingSameOrganization(shownHost, destinationHost string) bool {
    if shownHost == destinationHost {
        return true
    }
    shownOrganization := organizationalDomain(shownHost)
    return shownOrganization != "" && shownOrganization == organizationalDomain(destinationHost)
}
