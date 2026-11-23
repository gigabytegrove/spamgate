package transport

import (
 "net"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestControllerRejectsInvalidSocketPeersBeforeCredentialEvaluation(t *testing.T) {
 store, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 token := strings.Repeat("a", 32)
 _, loopback, err := net.ParseCIDR("127.0.0.0/8")
 if err != nil { t.Fatal(err) }
 controller := &RspamdController{Store: store, Token: token, Trusted: []*net.IPNet{loopback}}
 for _, tc := range []struct{name, remote string}{
  {"missing-port","127.0.0.1"},
  {"empty-port","127.0.0.1:"},
  {"zero-port","127.0.0.1:0"},
  {"negative-port","127.0.0.1:-1"},
  {"overflow-port","127.0.0.1:65536"},
  {"nonnumeric-port","127.0.0.1:mail"},
  {"non-ip-host","localhost:1234"},
  {"malformed-ip","127.0.0.999:1234"},
  {"zone-suffixed-ip","[fe80::1%eth0]:1234"},
 } {
  t.Run(tc.name, func(t *testing.T) {
   req := httptest.NewRequest(http.MethodGet,"http://localhost/ping",nil)
   req.RemoteAddr = tc.remote
   req.Header.Set("Password",token)
   req.Header.Set("X-Forwarded-For","127.0.0.1")
   if got := controller.controllerAuthorize(req); got != http.StatusForbidden {
    t.Fatalf("peer %q: status %d, want 403",tc.remote,got)
   }
  })
 }
 if got := controller.controllerAuthorize(nil); got != http.StatusForbidden {
  t.Fatalf("nil request: status %d, want 403",got)
 }
}

func TestControllerAcceptsWellFormedPeerForCredentialCheck(t *testing.T) {
 store, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 _, cidr, err := net.ParseCIDR("127.0.0.0/8")
 if err != nil { t.Fatal(err) }
 controller := &RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:strings.Repeat("a",32)}
 for _, addr := range []string{"127.0.0.1:1","127.0.0.1:65535"} {
  req := httptest.NewRequest(http.MethodGet,"http://localhost/ping",nil)
  req.RemoteAddr = addr
  // A well-formed trusted peer with no credential must reach the auth gate.
  if got := controller.controllerAuthorize(req); got != http.StatusUnauthorized {
   t.Fatalf("peer %q: status %d, want 401",addr,got)
  }
 }
}
