package transport

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestControllerCredentialAmbiguity(t *testing.T) {
    const secret = "valid-controller-secret-1234567890"
    cases := []struct {
        name string
        headers http.Header
        allow bool
    }{
        {"password", http.Header{"Password": {secret}}, true},
        {"bearer", http.Header{"Authorization": {"Bearer " + secret}}, true},
        {"lowercase-password", http.Header{"password": {secret}}, true},
        {"lowercase-bearer", http.Header{"authorization": {"Bearer " + secret}}, true},
        {"mixedcase-bearer", http.Header{"aUtHoRiZaTiOn": {"Bearer " + secret}}, true},
        {"missing", http.Header{}, false},
        {"both", http.Header{"Authorization": {"Bearer " + secret}, "Password": {secret}}, false},
        {"both-aliases", http.Header{"authorization": {"Bearer " + secret}, "PASSWORD": {secret}}, false},
        {"duplicate-password", http.Header{"Password": {secret, "bad"}}, false},
        {"duplicate-authorization", http.Header{"Authorization": {"Bearer " + secret, "Bearer bad"}}, false},
        {"duplicate-case-alias-password", http.Header{"Password": {secret}, "password": {"bad"}}, false},
        {"duplicate-case-alias-authorization", http.Header{"Authorization": {"Bearer " + secret}, "authorization": {"Bearer bad"}}, false},
        {"duplicate-identical-case-alias", http.Header{"Authorization": {"Bearer " + secret}, "AUTHORIZATION": {"Bearer " + secret}}, false},
        {"basic", http.Header{"Authorization": {"Basic " + secret}}, false},
        {"bare-authorization", http.Header{"Authorization": {secret}}, false},
        {"empty-bearer", http.Header{"Authorization": {"Bearer "}}, false},
        {"whitespace-bearer", http.Header{"Authorization": {"Bearer " + secret + " "}}, false},
        {"newline-password", http.Header{"Password": {secret + "\n"}}, false},
        {"comma-joined", http.Header{"Authorization": {"Bearer " + secret + ", Bearer bad"}}, false},
        {"empty-header-values", http.Header{"Password": {}}, false},
        {"empty-auth-values", http.Header{"Authorization": {}}, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, ok := controllerCredential(tc.headers)
            if ok != tc.allow { t.Fatalf("allowed=%v, want %v", ok, tc.allow) }
            if ok && got != secret { t.Fatalf("wrong credential accepted: %q", got) }
        })
    }
}

func TestControllerCredentialHTTPHeaders(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/stat", nil)
    req.Header.Add("Authorization", "Bearer valid")
    req.Header.Add("Authorization", "Bearer attacker")
    if _, ok := controllerCredential(req.Header); ok {
        t.Fatal("duplicate authorization header accepted")
    }
}

func TestControllerCredentialDirectMapCaseAliases(t *testing.T) {
    // Direct Header map assignments are legal and bypass canonicalization.
    h := http.Header{"Authorization": {"Bearer secret"}, "authorization": {"Bearer attacker"}}
    if _, ok := controllerCredential(h); ok { t.Fatal("case aliases accepted") }
    h = http.Header{"Password": {"secret"}, "PASSWORD": {"attacker"}}
    if _, ok := controllerCredential(h); ok { t.Fatal("password aliases accepted") }
}
