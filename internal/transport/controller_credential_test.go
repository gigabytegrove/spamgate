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
		auth []string
		password []string
		allow bool
	}{
		{name: "password", password: []string{secret}, allow: true},
		{name: "bearer", auth: []string{"Bearer " + secret}, allow: true},
		{name: "missing"},
		{name: "both", auth: []string{"Bearer " + secret}, password: []string{secret}},
		{name: "duplicate-password", password: []string{secret, "bad"}},
		{name: "duplicate-authorization", auth: []string{"Bearer " + secret, "Bearer bad"}},
		{name: "basic", auth: []string{"Basic " + secret}},
		{name: "bare-authorization", auth: []string{secret}},
		{name: "empty-bearer", auth: []string{"Bearer "}},
		{name: "whitespace-bearer", auth: []string{"Bearer " + secret + " "}},
		{name: "newline-password", password: []string{secret + "\n"}},
		{name: "comma-joined", auth: []string{"Bearer " + secret + ", Bearer bad"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			if tc.auth != nil { h["Authorization"] = tc.auth }
			if tc.password != nil { h["Password"] = tc.password }
			got, ok := controllerCredential(h)
			if ok != tc.allow { t.Fatalf("allowed=%v, want %v", ok, tc.allow) }
			if ok && got != secret { t.Fatalf("wrong credential accepted: %q", got) }
		})
	}
}

// No live controller is required to verify that duplicate header fields
// survive net/http request construction and reach the credential boundary.
func TestControllerCredentialHTTPHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/stat", nil)
	req.Header.Add("Authorization", "Bearer valid")
	req.Header.Add("Authorization", "Bearer attacker")
	if _, ok := controllerCredential(req.Header); ok {
		t.Fatal("duplicate authorization header accepted")
	}
}
